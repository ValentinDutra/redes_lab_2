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
#include <netinet/ether.h>

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

void sr_send_icmp_error_packet(uint8_t type,
                               uint8_t code,
                               struct sr_instance *sr,
                               uint32_t ipDst,
                               uint8_t *ipPacket)
{
  printf("Enviando paquete ICMP de error...\n");

  /* Obtener el encabezado IP del paquete original */
  sr_ip_hdr_t *orig_ip_hdr = (sr_ip_hdr_t *)(ipPacket + sizeof(sr_ethernet_hdr_t));

  printf("IP destino del paquete ICMP de error: %s\n", inet_ntoa(*(struct in_addr *)&ipDst));
  /* Encontrar la interfaz de salida basada en la dirección IP de destino */
  uint32_t destIP = ipDst;
  struct sr_rt *best_route = NULL;
  struct sr_rt *routing_entry = sr->routing_table;
  int longest_prefix = -1;

  printf("Buscando la mejor ruta para el paquete ICMP de error...\n");
  while (routing_entry)
  {
    uint32_t entry_dest = routing_entry->dest.s_addr;
    uint32_t entry_mask = routing_entry->mask.s_addr;
    uint32_t masked_destIP = destIP & entry_mask;

    printf("Verificando entrada de la tabla de enrutamiento: destino %s, máscara %s\n",
           inet_ntoa(*(struct in_addr *)&entry_dest),
           inet_ntoa(*(struct in_addr *)&entry_mask));

    uint32_t xor_result = ~(entry_dest ^ masked_destIP);

    int prefix_length = 0;
    int i;
    for (i = 31; i >= 0; i--)
    {
      if ((xor_result >> i) & 1)
        prefix_length++;
      else
        break;
    }

    /* Si la coincidencia es más específica, actualiza la mejor ruta */
    if (prefix_length > longest_prefix)
    {
      best_route = routing_entry;
      longest_prefix = prefix_length;
    }

    routing_entry = routing_entry->next;
  }

  if (!best_route)
  {
    printf("No se encontró una ruta válida para la dirección IP de destino: %s\n",
           inet_ntoa(*(struct in_addr *)&destIP));
    return;
  }

  printf("Ruta encontrada: destino %s, gateway %s, interfaz %s\n",
         inet_ntoa(*(struct in_addr *)&best_route->dest.s_addr),
         inet_ntoa(*(struct in_addr *)&best_route->gw.s_addr),
         best_route->interface);

  /* Obtener la interfaz de salida */
  struct sr_if *iface = sr_get_interface(sr, best_route->interface);
  if (!iface || !iface->addr)
  {
    printf("Error: No se encontró la interfaz de salida o la dirección MAC es nula.\n");
    return;
  }

  printf("Interfaz de salida encontrada: %s, dirección IP: %s\n", iface->name, inet_ntoa(*(struct in_addr *)&iface->ip));

  /* Crear el nuevo paquete ICMP de error */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *icmpPacket = (uint8_t *)malloc(len);
  if (!icmpPacket)
  {
    printf("Error al asignar memoria para el paquete ICMP.\n");
    return;
  }

  printf("Creando el paquete ICMP de error...\n");

  /* Configurar el encabezado Ethernet */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmpPacket;
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);
  printf("Encabezado Ethernet configurado: ether_shost: %s, tipo: %x\n",
         ether_ntoa((struct ether_addr *)eth_hdr->ether_shost), eth_hdr->ether_type);

  /* Configurar el encabezado IP */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmpPacket + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ip_hdr->ip_id = htons(0);
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_src = iface->ip;
  ip_hdr->ip_dst = ipDst;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  printf("Encabezado IP configurado: IP origen %s, IP destino %s\n",
         inet_ntoa(*(struct in_addr *)&ip_hdr->ip_src),
         inet_ntoa(*(struct in_addr *)&ip_hdr->ip_dst));

  /* Configurar el encabezado ICMP de error */
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmpPacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;
  memcpy(icmp_hdr->data, orig_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  printf("Encabezado ICMP configurado: tipo %d, código %d\n", icmp_hdr->icmp_type, icmp_hdr->icmp_code);

  /* Buscar la dirección MAC del siguiente salto en la caché ARP */
  uint32_t next_hop_ip = (best_route->gw.s_addr != 0) ? best_route->gw.s_addr : ipDst;
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);

  printf("Buscando la entrada ARP en la caché...\n");
  if (arp_entry)
  {
    printf("Entrada ARP encontrada: dirección MAC de destino: %s\n", ether_ntoa((struct ether_addr *)arp_entry->mac));
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, icmpPacket, len, best_route->interface);
    free(icmpPacket);
    printf("Paquete ICMP de error enviado correctamente.\n");
    free(arp_entry);
  }
  else
  {
    printf("No se encontró entrada ARP, encolando solicitud ARP para IP %s...\n", inet_ntoa(*(struct in_addr *)&next_hop_ip));
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, icmpPacket, len, best_route->interface);
    handle_arpreq(sr, req);
    printf("Solicitud ARP encolada.\n");
  }
}

void sr_handle_ip_packet(struct sr_instance *sr,
                         uint8_t *packet /* lent */,
                         unsigned int len,
                         uint8_t *srcAddr,
                         uint8_t *destAddr,
                         char *interface /* lent */,
                         sr_ethernet_hdr_t *eHdr)
{
  /* Obtener encabezado IP */
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Verificar si el paquete IP es para una de mis interfaces */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, ipHdr->ip_dst);

  if (myInterface != 0)
  {
    printf("El paquete está destinado a una de las interfaces locales.\n");
    fflush(stdout);

    if (ipHdr->ip_p == ip_protocol_icmp)
    {
      sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (icmpHdr->icmp_type == 8)
      {
        printf("ICMP Echo Request recibido. Generando Echo Reply...\n");
        fflush(stdout);

        /* Cambiar el tipo a Echo Reply */
        icmpHdr->icmp_type = 0;
        icmpHdr->icmp_code = 0;
        icmpHdr->icmp_sum = 0;
        icmpHdr->icmp_sum = cksum(icmpHdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

        /* Intercambiar direcciones IP */
        uint32_t tempIP = ipHdr->ip_src;
        ipHdr->ip_src = ipHdr->ip_dst;
        ipHdr->ip_dst = tempIP;

        /* Recalcular checksum IP */
        ipHdr->ip_sum = 0;
        ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));

        uint32_t destIP = ipHdr->ip_dst;

        struct sr_rt *best_route = NULL;
        struct sr_rt *routing_entry = sr->routing_table;
        int longest_prefix = -1;

        while (routing_entry)
        {
          uint32_t entry_dest = routing_entry->dest.s_addr;
          uint32_t entry_mask = routing_entry->mask.s_addr;
          uint32_t masked_destIP = destIP & entry_mask;

          uint32_t xor_result = ~(entry_dest ^ masked_destIP);

          int prefix_length = 0;
          int i;
          for (i = 31; i >= 0; i--)
          {
            if ((xor_result >> i) & 1)
              prefix_length++;
            else
              break;
          }

          /* Si la coincidencia es más específica, actualiza la mejor ruta*/
          if (prefix_length > longest_prefix)
          {
            best_route = routing_entry;
            longest_prefix = prefix_length;
          }

          routing_entry = routing_entry->next;
        }

        if (best_route)
        {
          sr_print_routing_entry(best_route);
          printf("Ruta encontrada: Destino , Gateway , Interfaz .\n");
          fflush(stdout);
        }

        if (!best_route)
        {
          printf("No se encontró una ruta válida. Enviando ICMP Network Unreachable.\n");
          sr_send_icmp_error_packet(3, 0, sr, destIP, packet);
          return;
        }

        struct sr_arpentry *arp_entry = NULL;
        uint32_t next_hop_ip = (best_route->gw.s_addr != 0) ? best_route->gw.s_addr : destIP;
        arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);

        if (arp_entry)
        {
          /* Crear un nuevo encabezado Ethernet para enviar el paquete */
          memcpy(eHdr->ether_shost, sr_get_interface(sr, best_route->interface)->addr, ETHER_ADDR_LEN);
          memcpy(eHdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

          /* Enviar el paquete */
          sr_send_packet(sr, packet, len, best_route->interface);
          free(arp_entry);
        }
        else
        {
          /* Encolar la solicitud ARP */
          struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet, len, best_route->interface);
          handle_arpreq(sr, req);
        }
        return;
      }
    }
    else if (ipHdr->ip_p == 17 || ipHdr->ip_p == 6)
    {
      /*Falta chequear la carga util UDP o TCP*/
      sr_send_icmp_error_packet(3, 3, sr, ipHdr->ip_src, packet);
      printf("Paquete IP no es ICMP. Enviando ICMP Port Unreachable.\n");
    }
    else
    {
      printf("Paquete IP no es ICMP. IGNORADO\n");
    }
    return;
  }
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