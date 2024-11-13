/**********************************************************************
 * file:  sr_router.c
 *
 * Descripción:
 *
 * Este archivo contiene todas las funciones que interactúan directamente
 * con la tabla de enrutamiento, así como el método de entrada principal
 * para el enrutamiento.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "pwospf_protocol.h"
#include "sr_pwospf.h"

uint8_t sr_multicast_mac[ETHER_ADDR_LEN];

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Inicializa el subsistema de enrutamiento
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  assert(sr);

  /* Inicializa el subsistema OSPF */
  pwospf_init(sr);

  /* Dirección MAC de multicast OSPF */
  sr_multicast_mac[0] = 0x01;
  sr_multicast_mac[1] = 0x00;
  sr_multicast_mac[2] = 0x5e;
  sr_multicast_mac[3] = 0x00;
  sr_multicast_mac[4] = 0x00;
  sr_multicast_mac[5] = 0x05;

  /* Inicializa la caché y el hilo de limpieza de la caché */
  sr_arpcache_init(&(sr->cache));

  /* Inicializa los atributos del hilo */
  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  /* Hilo para gestionar el timeout del caché ARP */
  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

#define ETHERTYPE_IP 0x0800

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0

#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_CODE_NET_UNREACHABLE 0
#define ICMP_CODE_HOST_UNREACHABLE 1
#define ICMP_CODE_PORT_UNREACHABLE 3

#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_CODE_TTL_EXCEEDED 0

#define IP_HDR_LEN sizeof(sr_ip_hdr_t)
#define ETHER_HDR_LENN sizeof(sr_ethernet_hdr_t)
#define ICMP_T3_HDR_LEN sizeof(sr_icmp_t3_hdr_t)
#define ICMP_DATA_SIZE 28

/* Función para encontrar la mejor ruta */
struct sr_rt *find_best_route(struct sr_instance *sr, uint32_t dest_ip)
{
  struct sr_rt *best_route = NULL;
  int longest_prefix = -1;
  struct sr_rt *rt_entry = sr->routing_table;

  while (rt_entry)
  {
    uint32_t rt_dest = rt_entry->dest.s_addr;
    uint32_t rt_mask = rt_entry->mask.s_addr;

    if ((rt_dest & rt_mask) == (dest_ip & rt_mask))
    {
      int prefix_length = __builtin_popcount(rt_mask);

      if (prefix_length > longest_prefix)
      {
        best_route = rt_entry;
        longest_prefix = prefix_length;
      }
    }

    rt_entry = rt_entry->next;
  }

  if (best_route)
  {
    char dest_str[INET_ADDRSTRLEN];
    char gw_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(best_route->dest), dest_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(best_route->gw), gw_str, INET_ADDRSTRLEN);
    printf("Ruta seleccionada: Destino %s, Gateway %s, Interfaz %s\n",
           dest_str, gw_str, best_route->interface);
  }
  else
  {
    printf("No se encontró una ruta para la IP destino: %s\n",
           inet_ntoa(*(struct in_addr *)&dest_ip));
  }

  return best_route;
}

/* Función para enviar el paquete al siguiente salto */
void send_packet_to_next_hop(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_rt *best_route)
{
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  uint32_t next_hop_ip = (best_route->gw.s_addr != 0) ? best_route->gw.s_addr : ((sr_ip_hdr_t *)(packet + ETHER_HDR_LENN))->ip_dst;

  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);

  if (arp_entry)
  {
    /* Obtener la interfaz de salida */
    struct sr_if *iface = sr_get_interface(sr, best_route->interface);

    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

    printf("Enviando paquete al siguiente salto %s a través de la interfaz %s\n",
           inet_ntoa(*(struct in_addr *)&next_hop_ip), iface->name);

    sr_send_packet(sr, packet, len, best_route->interface);
    free(arp_entry);
  }
  else
  {
    /* Encolar la solicitud ARP */
    printf("No se encontró entrada ARP para %s. Enviando solicitud ARP.\n",
           inet_ntoa(*(struct in_addr *)&next_hop_ip));

    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet, len, best_route->interface);
    handle_arpreq(sr, req);
  }
}

/* Función para construir el paquete ICMP de error */
uint8_t *build_icmp_error_packet(uint8_t type, uint8_t code, struct sr_if *iface, uint32_t ip_dst, sr_ip_hdr_t *orig_ip_hdr, unsigned int *len)
{
  *len = ETHER_HDR_LENN + IP_HDR_LEN + ICMP_T3_HDR_LEN;
  uint8_t *icmp_packet = (uint8_t *)malloc(*len);
  if (!icmp_packet)
  {
    fprintf(stderr, "Error al asignar memoria para el paquete ICMP.\n");
    return NULL;
  }

  /* Configurar el encabezado Ethernet */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
  memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ETHERTYPE_IP);

  /* Configurar el encabezado IP */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_packet + ETHER_HDR_LENN);
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = IP_HDR_LEN / 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(IP_HDR_LEN + ICMP_T3_HDR_LEN);
  ip_hdr->ip_id = htons(0);
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = IP_PROTOCOL_ICMP;
  ip_hdr->ip_src = iface->ip;
  ip_hdr->ip_dst = ip_dst;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = ip_cksum(ip_hdr, IP_HDR_LEN);

  /* Configurar el encabezado ICMP de error */
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + ETHER_HDR_LENN + IP_HDR_LEN);
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;
  memcpy(icmp_hdr->data, orig_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = icmp3_cksum(icmp_hdr, ICMP_T3_HDR_LEN);

  printf("Paquete ICMP de error construido: Tipo %d, Código %d\n", type, code);

  return icmp_packet;
}

void sr_send_icmp_error_packet(uint8_t type,
                               uint8_t code,
                               struct sr_instance *sr,
                               uint32_t ip_dst,
                               uint8_t *ip_packet)
{
  printf("Preparando para enviar paquete ICMP de error...\n");

  /* Obtener el encabezado IP del paquete original */
  sr_ip_hdr_t *orig_ip_hdr = (sr_ip_hdr_t *)(ip_packet + ETHER_HDR_LENN);

  /* Encontrar la mejor ruta para el destino */
  struct sr_rt *best_route = find_best_route(sr, orig_ip_hdr->ip_src);
  if (!best_route)
  {
    fprintf(stderr, "No se encontró una ruta válida para la dirección IP de destino: %s\n",
            inet_ntoa(*(struct in_addr *)&orig_ip_hdr->ip_src));
    return;
  }

  /* Obtener la interfaz de salida */
  struct sr_if *iface = sr_get_interface(sr, best_route->interface);
  if (!iface)
  {
    fprintf(stderr, "Error: No se encontró la interfaz de salida.\n");
    return;
  }

  /* Construir el paquete ICMP de error */
  unsigned int len;
  uint8_t *icmp_packet = build_icmp_error_packet(type, code, iface, orig_ip_hdr->ip_src, orig_ip_hdr, &len);
  if (!icmp_packet)
  {
    return;
  }

  /* Enviar el paquete al siguiente salto */
  send_packet_to_next_hop(sr, icmp_packet, len, best_route);
  free(icmp_packet);

  printf("Paquete ICMP de error enviado a %s\n", inet_ntoa(*(struct in_addr *)&orig_ip_hdr->ip_src));
}

/* Función para manejar solicitudes ICMP Echo Request */
void handle_icmp_echo_request(struct sr_instance *sr, uint8_t *packet, unsigned int len)
{
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(packet + ETHER_HDR_LENN);
  sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t *)(packet + ETHER_HDR_LENN + IP_HDR_LEN);

  /* Cambiar el tipo a Echo Reply */
  icmpHdr->icmp_type = ICMP_ECHO_REPLY;
  icmpHdr->icmp_code = 0;
  icmpHdr->icmp_sum = 0;
  icmpHdr->icmp_sum = icmp_cksum(icmpHdr, len - ETHER_HDR_LENN - IP_HDR_LEN);

  /* Intercambiar direcciones IP */
  uint32_t tempIP = ipHdr->ip_src;
  ipHdr->ip_src = ipHdr->ip_dst;
  ipHdr->ip_dst = tempIP;

  /* Recalcular checksum IP */
  ipHdr->ip_sum = 0;
  ipHdr->ip_sum = ip_cksum(ipHdr, IP_HDR_LEN);

  printf("Generando ICMP Echo Reply para %s\n", inet_ntoa(*(struct in_addr *)&ipHdr->ip_dst));

  struct sr_rt *best_route = find_best_route(sr, ipHdr->ip_dst);

  if (!best_route)
  {
    printf("No se encontró una ruta válida. Enviando ICMP Network Unreachable.\n");
    sr_send_icmp_error_packet(ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE, sr, ipHdr->ip_src, packet);
    return;
  }

  send_packet_to_next_hop(sr, packet, len, best_route);
}

void sr_handle_ip_packet(struct sr_instance *sr,
                         uint8_t *packet /* lent */,
                         unsigned int len,
                         uint8_t *srcAddr,
                         uint8_t *destAddr,
                         char *interface /* lent */,
                         sr_ethernet_hdr_t *eHdr)
{
  fprintf(stderr, "Comenzando a manejar paquete IP...\n");
  if (len < ETHER_HDR_LENN + IP_HDR_LEN)
  {
    fprintf(stderr, "Paquete demasiado pequeño. Ignorado.\n");
    return;
  }

  /* Obtener encabezado IP */
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(packet + ETHER_HDR_LENN);

  /* Verificar checksum IP */
  uint16_t received_cksum = ipHdr->ip_sum;
  ipHdr->ip_sum = 0;
  uint16_t calculated_cksum = ip_cksum(ipHdr, IP_HDR_LEN);

  if (received_cksum != calculated_cksum)
  {
    fprintf(stderr, "Checksum IP incorrecto. Paquete descartado.\n");
    return;
  }

  /* Restaurar checksum */
  ipHdr->ip_sum = received_cksum;

  printf("Chequeando que sea un paquete OSPFv2\n");
  /* Verificar si el paquete IP es de protocolo OSPFv2 */
  if (ipHdr->ip_p == 89)
  {
    printf("Paquete OSPFv2 recibido\n");
    struct in_addr hexa_to_addr;
    hexa_to_addr.s_addr = htonl(OSPF_AllSPFRouters);
    printf("IP multicast OSPF_AllSPFRouters: %s\n", inet_ntoa(hexa_to_addr));
    uint32_t multicast_ip;
    multicast_ip = hexa_to_addr.s_addr;
    printf("IP multicast OSPF_AllSPFRouters: %d\n", multicast_ip);

    printf("IP destino del paquete OSPFv2: %d\n", ipHdr->ip_dst);
    if (ipHdr->ip_dst == multicast_ip)
    {
      struct sr_if *myInterface = sr_get_interface_given_ip(sr, multicast_ip);

      printf("Paquete OSPFv2 recibido de %s y destinado a la dirección multicast OSPF_AllSPFRouters\n", inet_ntoa(*(struct in_addr *)&ipHdr->ip_src));
      sr_handle_pwospf_packet(sr, packet, len, myInterface);
      return;
    }
  }

  /* Verificar si el paquete IP es para una de mis interfaces */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, ipHdr->ip_dst);

  if (myInterface != 0)
  {
    printf("El paquete está destinado a esta interfaz: %s\n", myInterface->name);

    if (ipHdr->ip_p == IP_PROTOCOL_ICMP)
    {
      if (len < ETHER_HDR_LENN + IP_HDR_LEN + sizeof(sr_icmp_hdr_t))
      {
        fprintf(stderr, "Paquete ICMP demasiado pequeño. Ignorado.\n");
        return;
      }

      sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t *)(packet + ETHER_HDR_LENN + IP_HDR_LEN);

      if (icmpHdr->icmp_type == ICMP_ECHO_REQUEST)
      {
        printf("ICMP Echo Request recibido de %s\n", inet_ntoa(*(struct in_addr *)&ipHdr->ip_src));
        handle_icmp_echo_request(sr, packet, len);
      }
      else
      {
        printf("Tipo de ICMP %d no soportado. Ignorando paquete.\n", icmpHdr->icmp_type);
      }
    }
    else if (ipHdr->ip_p == IP_PROTOCOL_UDP || ipHdr->ip_p == IP_PROTOCOL_TCP)
    {
      printf("Paquete %s recibido. Enviando ICMP Port Unreachable.\n",
             (ipHdr->ip_p == IP_PROTOCOL_TCP) ? "TCP" : "UDP");
      sr_send_icmp_error_packet(ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, sr, ipHdr->ip_src, packet);
    }
    else
    {
      printf("Protocolo IP %d no soportado. Ignorando paquete.\n", ipHdr->ip_p);
    }
  }
  else
  {
    printf("El paquete no está destinado a una de las interfaces locales. Reenviando...\n");

    /* Verificar TTL */
    if (ipHdr->ip_ttl <= 1)
    {
      printf("TTL expirado. Enviando ICMP Time Exceeded a %s\n", inet_ntoa(*(struct in_addr *)&ipHdr->ip_src));
      sr_send_icmp_error_packet(ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TTL_EXCEEDED, sr, ipHdr->ip_src, packet);
      return;
    }

    /* Decrementar TTL y recalcular checksum */
    ipHdr->ip_ttl--;
    ipHdr->ip_sum = 0;
    ipHdr->ip_sum = ip_cksum(ipHdr, IP_HDR_LEN);

    struct sr_rt *best_route = find_best_route(sr, ipHdr->ip_dst);

    if (!best_route)
    {
      printf("No se encontró una ruta válida para %s. Enviando ICMP Network Unreachable.\n",
             inet_ntoa(*(struct in_addr *)&ipHdr->ip_dst));
      sr_send_icmp_error_packet(ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE, sr, ipHdr->ip_src, packet);
      return;
    }

    send_packet_to_next_hop(sr, packet, len, best_route);
  }

  printf("Paquete IP manejado correctamente.\n");
}

/*
 * ***** A partir de aquí no debería tener que modificar nada ****
 */

/* Envía todos los paquetes IP pendientes de una solicitud ARP */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                       struct sr_arpreq *arpReq,
                                       uint8_t *dhost,
                                       uint8_t *shost,
                                       struct sr_if *iface)
{

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL)
  {
    ethHdr = (sr_ethernet_hdr_t *)currPacket->buf;
    memcpy(ethHdr->ether_shost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_dhost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

    copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
    memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

    print_hdrs(copyPacket, currPacket->len);
    sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
    currPacket = currPacket->next;
  }
}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
                          uint8_t *packet /* lent */,
                          unsigned int len,
                          uint8_t *srcAddr,
                          uint8_t *destAddr,
                          char *interface /* lent */,
                          sr_ethernet_hdr_t *eHdr)
{

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo el cabezal ARP */
  sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo las direcciones MAC */
  unsigned char senderHardAddr[ETHER_ADDR_LEN], targetHardAddr[ETHER_ADDR_LEN];
  memcpy(senderHardAddr, arpHdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(targetHardAddr, arpHdr->ar_tha, ETHER_ADDR_LEN);

  /* Obtengo las direcciones IP */
  uint32_t senderIP = arpHdr->ar_sip;
  uint32_t targetIP = arpHdr->ar_tip;
  unsigned short op = ntohs(arpHdr->ar_op);

  /* Verifico si el paquete ARP es para una de mis interfaces */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, targetIP);

  if (op == arp_op_request)
  { /* Si es un request ARP */
    printf("**** -> It is an ARP request.\n");

    /* Si el ARP request es para una de mis interfaces */
    if (myInterface != 0)
    {
      printf("***** -> ARP request is for one of my interfaces.\n");

      /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
      printf("****** -> Add MAC->IP mapping of sender to my ARP cache.\n");
      sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);

      /* Construyo un ARP reply y lo envío de vuelta */
      printf("****** -> Construct an ARP reply and send it back.\n");
      memcpy(eHdr->ether_shost, (uint8_t *)myInterface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eHdr->ether_dhost, (uint8_t *)senderHardAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_sha, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_tha, senderHardAddr, ETHER_ADDR_LEN);
      arpHdr->ar_sip = targetIP;
      arpHdr->ar_tip = senderIP;
      arpHdr->ar_op = htons(arp_op_reply);

      /* Imprimo el cabezal del ARP reply creado */
      print_hdrs(packet, len);

      sr_send_packet(sr, packet, len, myInterface->name);
    }

    printf("******* -> ARP request processing complete.\n");
  }
  else if (op == arp_op_reply)
  { /* Si es un reply ARP */

    printf("**** -> It is an ARP reply.\n");

    /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
    printf("***** -> Add MAC->IP mapping of sender to my ARP cache.\n");
    struct sr_arpreq *arpReq = sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);

    if (arpReq != NULL)
    { /* Si hay paquetes pendientes */

      printf("****** -> Send outstanding packets.\n");
      sr_arp_reply_send_pending_packets(sr, arpReq, (uint8_t *)myInterface->addr, (uint8_t *)senderHardAddr, myInterface);
      sr_arpreq_destroy(&(sr->cache), arpReq);
    }
    printf("******* -> ARP reply processing complete.\n");
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *)packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len))
  {
    if (pktType == ethertype_arp)
    {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
    else if (pktType == ethertype_ip)
    {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

} /* end sr_ForwardPacket */