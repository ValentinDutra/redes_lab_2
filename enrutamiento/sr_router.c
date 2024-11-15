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

#define IP_PROTOCOL_ICMP 0x0001
#define IP_PROTOCOL_OSPFV2 89
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

/* Construir un paquete ICMP de error */
uint8_t *build_icmp_error_packet(uint8_t type,
                                 uint8_t code,
                                 struct sr_if *outInterface,
                                 uint32_t ipDst,
                                 sr_ip_hdr_t *ipHdr,
                                 unsigned int *len)
{
  Debug("-> ROUTER: Building ICMP error packet\n");
  *len = ETHER_HDR_LENN + IP_HDR_LEN + ICMP_T3_HDR_LEN;

  /* Crear un nuevo paquete */
  Debug("-> ROUTER: Creating new packet\n");
  uint8_t *packet = (uint8_t *)malloc(*len);
  if (packet == 0)
  {
    Debug("-> ROUTER: Error building ICMP error packet\n");
    return NULL;
  }

  /* Construir el cabezal Ethernet */
  Debug("-> ROUTER: Building Ethernet header\n");
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, outInterface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ETHERTYPE_IP);

  /* Construir el cabezal IP */
  Debug("-> ROUTER: Building IP header\n");
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + ETHER_HDR_LENN);
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = IP_HDR_LEN / 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(IP_HDR_LEN + ICMP_T3_HDR_LEN);
  ip_hdr->ip_id = htons(0);
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = IP_PROTOCOL_ICMP;
  ip_hdr->ip_src = outInterface->ip;
  ip_hdr->ip_dst = ipDst;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = ip_cksum(ip_hdr, IP_HDR_LEN);

  /* Construir el cabezal ICMP */
  Debug("-> ROUTER: Building ICMP header\n");
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + ETHER_HDR_LENN + IP_HDR_LEN);
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;
  memcpy(icmp_hdr->data, ipHdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = icmp3_cksum(icmp_hdr, ICMP_T3_HDR_LEN);

  Debug("-> ROUTER: ICMP error packet created: Type %d, Code %d\n", type, code);
  print_hdrs(packet, *len);
  return packet;
}

/* Encontrar la mejor ruta*/
struct sr_rt *find_best_route(struct sr_instance *sr, uint32_t ipDst)
{
  Debug("-> ROUTER: Finding best route\n");
  struct sr_rt *best_route = 0;
  int longest_prefix = -1;
  struct sr_rt *rt_entry = sr->routing_table;

  Debug("-> ROUTER: IP destination: \n");
  print_addr_ip_int(ipDst);

  while (rt_entry)
  {
    uint32_t rt_dest = rt_entry->dest.s_addr;
    uint32_t rt_mask = rt_entry->mask.s_addr;

    if ((rt_dest & rt_mask) == (ipDst & rt_mask))
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

  if (best_route != 0)
  {
    Debug("-> ROUTER: Best route found\n");
    char dest_str[INET_ADDRSTRLEN];
    char gw_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(best_route->dest), dest_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(best_route->gw), gw_str, INET_ADDRSTRLEN);
    Debug("-> ROUTER: Destination: %s, Gateway: %s, Interface: %s\n", dest_str, gw_str, best_route->interface);
  }
  else
  {
    Debug("-> ROUTER: No route found\n");
  }
  return best_route;
} /* -- find_best_route -- */

/* Enviar el paquete al siguiente salto*/
void send_packet_to_next_hop(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_rt *best_route)
{
  Debug("-> ROUTER: Sending packet to next hop\n");
  sr_ethernet_hdr_t *ethHdr = (sr_ethernet_hdr_t *)packet;
  uint32_t nextHop = (best_route->gw.s_addr != 0) ? best_route->gw.s_addr : ((sr_ip_hdr_t *)(packet + ETHER_HDR_LENN))->ip_dst;

  struct in_addr dest_ip_addr;
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + ETHER_HDR_LENN);
  dest_ip_addr.s_addr = ip_header->ip_dst;

  Debug("-> ROUTER: Next hop: \n");
  print_addr_ip_int(nextHop);
  Debug("\n");
  Debug("-> ROUTER: Destination IP: \n");
  print_addr_ip_int(dest_ip_addr.s_addr);

  Debug("-> ROUTER: Looking for ARP entry\n");
  struct sr_arpentry *arpEntry = sr_arpcache_lookup(&sr->cache, nextHop);

  if (arpEntry != 0)
  {
    Debug("-> ROUTER: ARP entry found\n");
    struct sr_if *outInterface = sr_get_interface(sr, best_route->interface);

    Debug("-> ROUTER: Outgoing interface: %s\n", outInterface->name);

    memcpy(ethHdr->ether_shost, outInterface->addr, ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);

    Debug("-> ROUTER: Sending packet to next hop: \n");
    print_hdrs(packet, len);
    Debug("-> ROUTER: Sending packet to interface: %s\n", outInterface->name);

    int response;
    response = sr_send_packet(sr, packet, len, outInterface->name);
    free(arpEntry);
    (response == -1) ? Debug("-> ROUTER: Error sending packet\n") : Debug("-> ROUTER: Packet sent\n");
    return;
  }
  else
  {
    Debug("-> ROUTER: ARP entry not found\n");
    Debug("-> ROUTER: Queuing ARP request\n");
    struct sr_arpreq *arpReq = sr_arpcache_queuereq(&sr->cache, nextHop, packet, len, best_route->interface);
    handle_arpreq(sr, arpReq);
    return;
  }
} /* -- send_packet_to_next_hop -- */
/* Maneja una solicitud de eco ICMP */

void handle_icmp_echo_request(struct sr_instance *sr,
                              uint8_t *packet /* lent */,
                              unsigned int len)
{
  Debug("-> ROUTER: Handling ICMP echo request\n");
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(packet + ETHER_HDR_LENN);
  sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t *)(packet + ETHER_HDR_LENN + IP_HDR_LEN);

  /* Crear un nuevo paquete */
  Debug("-> ROUTER: Updating TYPE packet\n");
  icmpHdr->icmp_type = ICMP_ECHO_REPLY;
  icmpHdr->icmp_code = ICMP_ECHO_REPLY;
  icmpHdr->icmp_sum = 0;
  icmpHdr->icmp_sum = icmp_cksum(icmpHdr, len - ETHER_HDR_LENN - IP_HDR_LEN);

  /* Intercambiar direcciones IP */
  Debug("-> ROUTER: Swapping IP addresses\n");
  Debug("-> ROUTER: IP Source:\n");
  print_addr_ip_int(ipHdr->ip_src);
  Debug("\n");
  Debug("-> ROUTER: IP Destination:\n");
  print_addr_ip_int(ipHdr->ip_dst);

  uint32_t temp = ipHdr->ip_src;
  ipHdr->ip_src = ipHdr->ip_dst;
  ipHdr->ip_dst = temp;

  Debug("-> ROUTER: Generating ICMP echo reply\n");
  print_hdrs(packet, len);

  struct sr_rt *best_route = find_best_route(sr, ipHdr->ip_dst);

  if (best_route == 0)
  {
    Debug("-> ROUTER: No route found\n");
    sr_send_icmp_error_packet(ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE, sr, ipHdr->ip_src, packet);
    return;
  }

  send_packet_to_next_hop(sr, packet, len, best_route);
  return;
} /* -- handle_icmp_echo_request -- */

/* Envía un paquete ICMP de error */
void sr_send_icmp_error_packet(uint8_t type,
                               uint8_t code,
                               struct sr_instance *sr,
                               uint32_t ipDst,
                               uint8_t *ipPacket)
{

  /* COLOQUE AQUÍ SU CÓDIGO*/
  Debug("-> ROUTER: Preparing ICMP error packet\n");
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(ipPacket + ETHER_HDR_LENN);

  /* Encontrar la mejor ruta */
  struct sr_rt *best_route = find_best_route(sr, ipDst);
  if (best_route != 0)
  {
    Debug("-> ROUTER: Best route not found\n");
    return;
  }

  /* Obtener la interfaz de salida */
  Debug("-> ROUTER: Getting output interface\n");
  struct sr_if *outInterface = sr_get_interface(sr, best_route->interface);

  if (outInterface != 0)
  {
    Debug("-> ROUTER: Output interface not found\n");
    return;
  }

  /* Crear un nuevo paquete */
  unsigned int len;
  uint8_t *packet = build_icmp_error_packet(type, code, outInterface, ipDst, ipHdr, &len);
  if (packet == 0)
  {
    Debug("-> ROUTER: Error building ICMP error packet\n");
    return;
  }

  /* Enviar el paquete */
  send_packet_to_next_hop(sr, packet, len, best_route);
  free(packet);
  return;
} /* -- sr_send_icmp_error_packet -- */

void sr_handle_ip_packet(struct sr_instance *sr,
                         uint8_t *packet /* lent */,
                         unsigned int len,
                         uint8_t *srcAddr,
                         uint8_t *destAddr,
                         char *interface /* lent */,
                         sr_ethernet_hdr_t *eHdr)
{

  /*
   * COLOQUE ASÍ SU CÓDIGO
   * SUGERENCIAS:
   * - Obtener el cabezal IP y direcciones
   * - Verificar si el paquete es para una de mis interfaces o si hay una coincidencia en mi tabla de enrutamiento
   * - Si no es para una de mis interfaces y no hay coincidencia en la tabla de enrutamiento, enviar ICMP net unreachable
   * - Sino, si es para mí, verificar si es un paquete ICMP echo request y responder con un echo reply
   * - Sino, verificar TTL, ARP y reenviar si corresponde (puede necesitar una solicitud ARP y esperar la respuesta)
   * - No olvide imprimir los mensajes de depuración
   */

  /* Obtener encabezado IP */
  Debug("-> ROUTER: IP packet received\n");
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(packet + ETHER_HDR_LENN);

  /* Obtener direcciones IP */
  Debug("-> ROUTER: Source IP: \n");
  print_addr_ip_int(ipHdr->ip_src);
  Debug("\n");
  Debug("-> ROUTER: Destination IP: \n");
  print_addr_ip_int(ipHdr->ip_dst);

  /* Verificar checksum */
  Debug("-> ROUTER: Verifying IP checksum\n");
  uint16_t received_cksum = ipHdr->ip_sum;
  ipHdr->ip_sum = 0;
  uint16_t calculated_cksum = ip_cksum(ipHdr, IP_HDR_LEN);

  if (received_cksum != calculated_cksum)
  {
    Debug("-> ROUTER: IP checksum incorrect\n");
    return;
  }
  Debug("-> ROUTER: IP checksum correct\n");

  ipHdr->ip_sum = received_cksum;

  /* Verificar si el paquete es para una de mis interfaces */
  Debug("-> ROUTER: Checking if packet is for one of my interfaces\n");
  struct sr_if *myInterface = sr_get_interface(sr, interface);
  if (myInterface != 0)
  {
    Debug("-> ROUTER: Packet is for one of my interfaces\n");
    Debug("-> ROUTER: Interface: %s\n", myInterface->name);
    if (ipHdr->ip_p == IP_PROTOCOL_OSPFV2)
    {
      Debug("-> ROUTER: OSPF packet received\n");

      Debug("-> ROUTER: OSPF packet send by:\n");
      print_addr_ip_int(ipHdr->ip_src);

      Debug("-> ROUTER: OSPF packet to:\n");
      print_addr_ip_int(ipHdr->ip_dst);

      Debug("-> ROUTER: Verifying length\n");
      if (len < ETHER_HDR_LENN + IP_HDR_LEN)
      {
        Debug("-> ROUTER: Length is not enough\n");
        return;
      }

      Debug("-> ROUTER: Verifying OSPF checksum\n");
      uint16_t received_cksum = ipHdr->ip_sum;
      ipHdr->ip_sum = 0;
      uint16_t calculated_cksum = ip_cksum(ipHdr, len - ETHER_HDR_LENN);
      if (received_cksum != calculated_cksum)
      {
        Debug("-> ROUTER: OSPF checksum incorrect\n");
        return;
      }
      Debug("-> ROUTER: OSPF checksum correct\n");
      ipHdr->ip_sum = received_cksum;

      Debug("-> ROUTER: Checking if IP destination is multicast\n");
      struct in_addr dest_addr;
      dest_addr.s_addr = ipHdr->ip_dst;

      uint32_t multicast_addr = OSPF_AllSPFRouters;

      Debug("-> ROUTER: IP destination:\n");
      print_addr_ip_int(dest_addr.s_addr);
      Debug("\n");
      Debug("-> ROUTER: Multicast address:\n");
      print_addr_ip_int(multicast_addr);

      if (ipHdr->ip_dst == multicast_addr)
      {
        Debug("-> ROUTER: IP destination is multicast\n");
        Debug("-> ROUTER: Sending OSPF packet to subsystem, by: %s and to: %s\n", inet_ntoa(*(struct in_addr *)&ipHdr->ip_src), inet_ntoa(*(struct in_addr *)&ipHdr->ip_dst));
        sr_handle_pwospf_packet(sr, packet, len, myInterface);
        return;
      }

      Debug("-> ROUTER: IP destination is not multicast\n");
      return;
    }

    if (ipHdr->ip_p == IP_PROTOCOL_ICMP)
    {
      Debug("-> ROUTER: ICMP packet received\n");

      Debug("-> ROUTER: Verifying length\n");
      if (len < ETHER_HDR_LENN + IP_HDR_LEN + sizeof(sr_icmp_hdr_t))
      {
        Debug("-> ROUTER: Length is not enough\n");
        return;
      }

      sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t *)(packet + ETHER_HDR_LENN + IP_HDR_LEN);

      Debug("-> ROUTER: Verifying ICMP checksum\n");
      uint16_t received_cksum = icmpHdr->icmp_sum;
      icmpHdr->icmp_sum = 0;
      uint16_t calculated_cksum = icmp_cksum(icmpHdr, len - ETHER_HDR_LENN - IP_HDR_LEN);
      if (received_cksum != calculated_cksum)
      {
        Debug("-> ROUTER: ICMP checksum incorrect\n");
        return;
      }

      Debug("-> ROUTER: ICMP checksum correct\n");
      icmpHdr->icmp_sum = received_cksum;

      if (icmpHdr->icmp_type == ICMP_ECHO_REQUEST)
      {
        Debug("-> ROUTER: ICMP echo request received\n");
        Debug("-> ROUTER: Sending ICMP echo reply to: %s\n", inet_ntoa(*(struct in_addr *)&ipHdr->ip_src));
        handle_icmp_echo_request(sr, packet, len);
        return;
      }

      Debug("-> ROUTER: ICMP type not supported\n");
      return;
    }

    if (ipHdr->ip_p == IP_PROTOCOL_UDP || ipHdr->ip_p == IP_PROTOCOL_TCP)
    {
      Debug("-> ROUTER: UDP/TCP packet received\n");
      Debug("-> ROUTER: Sending ICMP port unreachable\n");
      Debug("-> ROUTER: Sending ICMP port unreachable to: %s\n", inet_ntoa(*(struct in_addr *)&ipHdr->ip_src));
      sr_send_icmp_error_packet(ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, sr, ipHdr->ip_src, packet);
      return;
    }

    Debug("-> ROUTER: Protocol not supported\n");
    return;
  }
  else
  {
    Debug("-> ROUTER: Packet is not for one of my interfaces\n");

    /* Verificar TTL */
    Debug("-> ROUTER: Verifying TTL\n");
    if (ipHdr->ip_ttl <= 1)
    {
      Debug("-> ROUTER: TTL is less than 1\n");
      sr_send_icmp_error_packet(ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TTL_EXCEEDED, sr, ipHdr->ip_src, packet);
      return;
    }

    /* Decrementar TTL y recalcular checksum */
    Debug("-> ROUTER: Decrementing TTL and recalculating checksum\n");
    ipHdr->ip_ttl--;
    ipHdr->ip_sum = 0;
    ipHdr->ip_sum = ip_cksum(ipHdr, IP_HDR_LEN);

    /* Buscar la mejor ruta */
    struct sr_rt *best_route = find_best_route(sr, ipHdr->ip_dst);

    if (best_route != 0)
    {
      Debug("-> ROUTER: Best route not found\n");
      sr_send_icmp_error_packet(ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE, sr, ipHdr->ip_src, packet);
      return;
    }

    send_packet_to_next_hop(sr, packet, len, best_route);
    return;
  }
  Debug("-> ROUTER: Packet processed\n");
  return;
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