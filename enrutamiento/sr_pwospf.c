/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 *
 * Descripción:
 * Este archivo contiene las funciones necesarias para el manejo de los paquetes
 * OSPF.
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>

#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "sr_utils.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_rt.h"
#include "pwospf_neighbors.h"
#include "pwospf_topology.h"
#include "dijkstra.h"

/*pthread_t hello_thread;*/
pthread_t g_hello_packet_thread;
pthread_t g_all_lsu_thread;
pthread_t g_lsu_thread;
pthread_t g_neighbors_thread;
pthread_t g_topology_entries_thread;
pthread_t g_rx_lsu_thread;
pthread_t g_dijkstra_thread;

pthread_mutex_t g_dijkstra_mutex = PTHREAD_MUTEX_INITIALIZER;

struct in_addr g_router_id;
uint8_t g_ospf_multicast_mac[ETHER_ADDR_LEN];
struct ospfv2_neighbor *g_neighbors;
struct pwospf_topology_entry *g_topology;
uint16_t g_sequence_num;

/* -- Declaración de hilo principal de la función del subsistema pwospf --- */
static void *pwospf_run_thread(void *arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Configura las estructuras de datos internas para el subsistema pwospf
 * y crea un nuevo hilo para el subsistema pwospf.
 *
 * Se puede asumir que las interfaces han sido creadas e inicializadas
 * en este punto.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance *sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys *)malloc(sizeof(struct
                                                            pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    g_router_id.s_addr = 0;

    /* Defino la MAC de multicast a usar para los paquetes HELLO */
    g_ospf_multicast_mac[0] = 0x01;
    g_ospf_multicast_mac[1] = 0x00;
    g_ospf_multicast_mac[2] = 0x5e;
    g_ospf_multicast_mac[3] = 0x00;
    g_ospf_multicast_mac[4] = 0x00;
    g_ospf_multicast_mac[5] = 0x05;

    g_neighbors = NULL;

    g_sequence_num = 0;

    struct in_addr zero;
    zero.s_addr = 0;
    g_neighbors = create_ospfv2_neighbor(zero);
    g_topology = create_ospfv2_topology_entry(zero, zero, zero, zero, zero, 0);

    /* -- start thread subsystem -- */
    if (pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr))
    {
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */

/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_lock(&subsys->lock))
    {
        assert(0);
    }
}

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_unlock(&subsys->lock))
    {
        assert(0);
    }
}

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Hilo principal del subsistema pwospf.
 *
 *---------------------------------------------------------------------*/

static void *pwospf_run_thread(void *arg)
{
    sleep(5);

    struct sr_instance *sr = (struct sr_instance *)arg;

    /* Set the ID of the router */
    while (g_router_id.s_addr == 0)
    {
        struct sr_if *int_temp = sr->if_list;
        while (int_temp != NULL)
        {
            if (int_temp->ip > g_router_id.s_addr)
            {
                g_router_id.s_addr = int_temp->ip;
            }

            int_temp = int_temp->next;
        }
    }
    Debug("\n\nPWOSPF: Selecting the highest IP address on a router as the router ID\n");
    Debug("-> PWOSPF: The router ID is [%s]\n", inet_ntoa(g_router_id));

    Debug("\nPWOSPF: Detecting the router interfaces and adding their networks to the routing table\n");
    struct sr_if *int_temp = sr->if_list;
    while (int_temp != NULL)
    {
        struct in_addr ip;
        ip.s_addr = int_temp->ip;
        struct in_addr gw;
        gw.s_addr = 0x00000000;
        struct in_addr mask;
        mask.s_addr = int_temp->mask;
        struct in_addr network;
        network.s_addr = ip.s_addr & mask.s_addr;

        if (check_route(sr, network) == 0)
        {
            Debug("-> PWOSPF: Adding the directly connected network [%s, ", inet_ntoa(network));
            Debug("%s] to the routing table\n", inet_ntoa(mask));
            sr_add_rt_entry(sr, network, gw, mask, int_temp->name, 1);
        }
        int_temp = int_temp->next;
    }

    Debug("\n-> PWOSPF: Printing the forwarding table\n");
    sr_print_routing_table(sr);

    pthread_create(&g_hello_packet_thread, NULL, send_hellos, sr);
    pthread_create(&g_all_lsu_thread, NULL, send_all_lsu, sr);
    pthread_create(&g_neighbors_thread, NULL, check_neighbors_life, sr);
    pthread_create(&g_topology_entries_thread, NULL, check_topology_entries_age, sr);

    return NULL;
} /* -- run_ospf_thread -- */

/***********************************************************************************
 * Métodos para el manejo de los paquetes HELLO y LSU
 * SU CÓDIGO DEBERÍA IR AQUÍ
 * *********************************************************************************/

#define OSPF_PROTOCOL_TYPE 89
#define OSPF_LSU_TIMEOUT 30

#define OSPF_HDR_LEN sizeof(ospfv2_hdr_t)
#define OSPF_HELLO_HDR_LEN sizeof(ospfv2_hello_hdr_t)
#define IP_HDR_LEN sizeof(sr_ip_hdr_t)
#define ETHER_HDR_LENN sizeof(sr_ethernet_hdr_t)
#define OSPF_LSU_HDR_LEN sizeof(ospfv2_lsu_hdr_t)
#define LSA_LEN sizeof(ospfv2_lsa_t)
#define ETHERTYPE_IP 0x0800

/*---------------------------------------------------------------------
 * Method: check_neighbors_life
 *
 * Chequea si los vecinos están vivos
 *
 *---------------------------------------------------------------------*/

void *check_neighbors_life(void *arg)
{
    struct sr_instance *sr = (struct sr_instance *)arg;
    /*
    Cada 1 segundo, chequea la lista de vecinos.
    Si hay un cambio, se debe ajustar el neighbor id en la interfaz.
    */
    return NULL;
} /* -- check_neighbors_life -- */

/*---------------------------------------------------------------------
 * Method: check_topology_entries_age
 *
 * Check if the topology entries are alive
 * and if they are not, remove them from the topology table
 *
 *---------------------------------------------------------------------*/

void *check_topology_entries_age(void *arg)
{
    struct sr_instance *sr = (struct sr_instance *)arg;

    /*
    Cada 1 segundo, chequea el tiempo de vida de cada entrada
    de la topologia.
    Si hay un cambio en la topología, se llama a la función de Dijkstra
    en un nuevo hilo.
    Se sugiere también imprimir la topología resultado del chequeo.
    */

    return NULL;
} /* -- check_topology_entries_age -- */

/*---------------------------------------------------------------------
 * Method: send_hellos
 *
 * Para cada interfaz y cada helloint segundos, construye mensaje
 * HELLO y crea un hilo con la función para enviar el mensaje.
 *
 *---------------------------------------------------------------------*/

void *send_hellos(void *arg)
{
    Debug("\nPWOSPF: Starting to send HELLOs\n");
    struct sr_instance *sr = (struct sr_instance *)arg;

    Debug("\nPWOSPF: Counting the number of interfaces\n");
    struct sr_if *iface;
    int num_interfaces = 0;
    for (iface = sr->if_list; iface != NULL; iface = iface->next)
    {
        num_interfaces++;
    }
    Debug("-> PWOSPF: Number of interfaces = %d\n", num_interfaces);
    /* While true */
    while (1)
    {
        /* Se ejecuta cada 1 segundo */
        usleep(1000000);

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);

        /* Chequeo todas las interfaces para enviar el paquete HELLO */
        for (iface = sr->if_list; iface != NULL; iface = iface->next)
        {
            /* Cada interfaz matiene un contador en segundos para los HELLO*/
            if (iface->helloint > OSPF_DEFAULT_HELLOINT)
            {
                iface->helloint++;
                powspf_hello_lsu_param_t *hello_param = (powspf_hello_lsu_param_t *)malloc(sizeof(powspf_hello_lsu_param_t));
                hello_param->sr = sr;
                hello_param->interface = iface;

                pthread_t hello_thread;
                pthread_create(&hello_thread, NULL, send_hello_packet, hello_param);
                pthread_detach(hello_thread);
                /* Reiniciar el contador de segundos para HELLO */
                iface->helloint = 0;
            }
            else
            {
                iface->helloint++;
            }
        }

        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
        Debug("-> PWOSPF: HELLOs sent\n");
    };

    return NULL;
} /* -- send_hellos -- */

/*---------------------------------------------------------------------
 * Method: send_hello_packet
 *
 * Recibe un mensaje HELLO, agrega cabezales y lo envía por la interfaz
 * correspondiente.
 *
 *---------------------------------------------------------------------*/

void *send_hello_packet(void *arg)
{
    powspf_hello_lsu_param_t *hello_param = ((powspf_hello_lsu_param_t *)(arg));

    Debug("\n\nPWOSPF: Constructing HELLO packet for interface %s: \n", hello_param->interface->name);

    /* Inicializo cabezal Ethernet */
    Debug("-> PWOSPF: Packet length\n");
    unsigned int packet_len;
    packet_len = ETHER_HDR_LENN + IP_HDR_LEN + OSPF_HDR_LEN + OSPF_HELLO_HDR_LEN;

    Debug("-> PWOSPF: Creating packet\n");
    uint8_t *packet;
    packet = (uint8_t *)malloc(packet_len);
    if (packet == 0)
    {
        Debug("-> PWOSPF: Error creating packet\n");
        return NULL;
    }
    Debug("-> PWOSPF: Packet created\n");
    memset(packet, 0, packet_len);

    Debug("-> PWOSPF: Setting Ethernet header\n");
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    /* Seteo la dirección MAC de multicast para la trama a enviar */
    Debug("-> PWOSPF: Setting MAC address\n");
    memcpy(eth_hdr->ether_dhost, g_ospf_multicast_mac, ETHER_ADDR_LEN);

    /* Seteo la dirección MAC origen con la dirección de mi interfaz de salida */
    Debug("-> PWOSPF: Setting source MAC address\n");
    memcpy(eth_hdr->ether_shost, hello_param->interface->addr, ETHER_ADDR_LEN);

    /* Seteo el ether_type en el cabezal Ethernet */
    Debug("-> PWOSPF: Setting ether_type\n");
    eth_hdr->ether_type = htons(ETHERTYPE_IP);

    /* Inicializo cabezal IP */
    Debug("-> PWOSPF: Setting IP header\n");
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + ETHER_HDR_LENN);

    /* Seteo el protocolo en el cabezal IP para ser el de OSPF (89) */
    Debug("-> PWOSPF: Setting IP protocol\n");
    ip_hdr->ip_p = OSPF_PROTOCOL_TYPE;

    /* Seteo IP origen con la IP de mi interfaz de salida */
    Debug("-> PWOSPF: Setting IP source\n");
    uint32_t reorganize_source_ip_bytes = htonl(hello_param->interface->ip);
    ip_hdr->ip_src = reorganize_source_ip_bytes;

    /* Seteo IP destino con la IP de Multicast dada: OSPF_AllSPFRouters  */
    Debug("-> PWOSPF: Setting IP destination\n");
    ip_hdr->ip_dst = OSPF_AllSPFRouters;

    /* Calculo y seteo el chechsum IP*/
    Debug("-> PWOSPF: Calculating IP checksum\n");
    uint16_t packet_len_wo_hdrs;
    packet_len_wo_hdrs = packet_len - ETHER_HDR_LENN;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = ip_cksum(ip_hdr, packet_len_wo_hdrs);

    /* Inicializo cabezal de PWOSPF con version 2 y tipo HELLO */
    Debug("-> PWOSPF: Setting OSPF header\n");
    ospfv2_hdr_t *ospf_hdr = (ospfv2_hdr_t *)(packet + ETHER_HDR_LENN + IP_HDR_LEN);
    ospf_hdr->version = OSPF_V2;
    ospf_hdr->type = OSPF_TYPE_HELLO;

    /* Seteo el Router ID con mi ID*/
    Debug("-> PWOSPF: Setting Router ID\n");
    ospf_hdr->rid = g_router_id.s_addr;

    /* Seteo el Area ID en 0 */
    Debug("-> PWOSPF: Setting Area ID\n");
    ospf_hdr->aid = 0;
    /* Seteo el Authentication Type y Authentication Data en 0*/
    Debug("-> PWOSPF: Setting Authentication Type and Data\n");
    ospf_hdr->autype = 0;
    ospf_hdr->audata = 0;

    Debug("-> PWOSPF: Setting OSPF header \n");
    ospfv2_hello_hdr_t *ospf_hello_hdr = (ospfv2_hello_hdr_t *)(packet + ETHER_HDR_LENN + IP_HDR_LEN + OSPF_HDR_LEN);
    /* Seteo máscara con la máscara de mi interfaz de salida */
    Debug("-> PWOSPF: Setting Mask\n");
    ospf_hello_hdr->nmask = hello_param->interface->mask;

    /* Seteo Hello Interval con OSPF_DEFAULT_HELLOINT */
    Debug("-> PWOSPF: Setting Hello Interval\n");
    ospf_hello_hdr->helloint = OSPF_DEFAULT_HELLOINT;

    /* Seteo Padding en 0*/
    Debug("-> PWOSPF: Setting Padding\n");
    ospf_hello_hdr->padding = 0;

    /* Calculo y actualizo el checksum del cabezal OSPF */
    Debug("-> PWOSPF: Calculating OSPF checksum\n");
    uint16_t packet_len_wo_eth_ip_hdrs;
    packet_len_wo_eth_ip_hdrs = packet_len - ETHER_HDR_LENN - IP_HDR_LEN;
    ospf_hdr->csum = 0;
    ospf_hdr->csum = ospfv2_cksum(ospf_hdr, packet_len_wo_eth_ip_hdrs);

    /* Envío el paquete HELLO */
    Debug("-> PWOSPF: Sending HELLO Packet\n");
    int response;
    response = sr_send_packet(hello_param->sr, packet, packet_len, hello_param->interface->name);
    (response == 0) ? Debug("-> PWOSPF: HELLO Packet sent\n") : Debug("-> PWOSPF: HELLO Packet not sent\n");

    /* Imprimo información del paquete HELLO enviado */
    struct in_addr ip_addr;
    ip_addr.s_addr = hello_param->interface->ip;
    struct in_addr mask_addr;
    mask_addr.s_addr = hello_param->interface->mask;
    Debug("-> PWOSPF: Sending HELLO Packet of length = %d, out of the interface: %s\n", packet_len, hello_param->interface->name);
    Debug("      [Router ID = %s]\n", htons(ospf_hdr->rid));
    Debug("      [Router IP = %s]\n", inet_ntoa(ip_addr));
    Debug("      [Network Mask = %s]\n", inet_ntoa(mask_addr));

    return NULL;
} /* -- send_hello_packet -- */

/*---------------------------------------------------------------------
 * Method: send_all_lsu
 *
 * Construye y envía LSUs cada 30 segundos
 *
 *---------------------------------------------------------------------*/

void *send_all_lsu(void *arg)
{
    struct sr_instance *sr = (struct sr_instance *)arg;

    /* while true*/
    while (1)
    {
        /* Se ejecuta cada OSPF_DEFAULT_LSUINT segundos */
        usleep(OSPF_DEFAULT_LSUINT * 1000000);

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);

        /* Recorro todas las interfaces para enviar el paquete LSU */
        /* Si la interfaz tiene un vecino, envío un LSU */

        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
    };

    return NULL;
} /* -- send_all_lsu -- */

/*---------------------------------------------------------------------
 * Method: send_lsu
 *
 * Construye y envía paquetes LSU a través de una interfaz específica
 *
 *---------------------------------------------------------------------*/

void *send_lsu(void *arg)
{
    powspf_hello_lsu_param_t *lsu_param = ((powspf_hello_lsu_param_t *)(arg));

    /* Solo envío LSUs si del otro lado hay un router*/

    /* Construyo el LSU */
    Debug("\n\nPWOSPF: Constructing LSU packet\n");

    /* Inicializo cabezal Ethernet */
    /* Dirección MAC destino la dejo para el final ya que hay que hacer ARP */

    /* Inicializo cabezal IP*/
    /* La IP destino es la del vecino contectado a mi interfaz*/

    /* Inicializo cabezal de OSPF*/

    /* Seteo el número de secuencia y avanzo*/
    /* Seteo el TTL en 64 y el resto de los campos del cabezal de LSU */
    /* Seteo el número de anuncios con la cantidad de rutas a enviar. Uso función count_routes */

    /* Creo el paquete y seteo todos los cabezales del paquete a transmitir */

    /* Creo cada LSA iterando en las enttadas de la tabla */
    /* Solo envío entradas directamente conectadas y agreagadas a mano*/
    /* Creo LSA con subnet, mask y routerID (id del vecino de la interfaz)*/

    /* Calculo el checksum del paquete LSU */

    /* Me falta la MAC para poder enviar el paquete, la busco en la cache ARP*/
    /* Envío el paquete si obtuve la MAC o lo guardo en la cola para cuando tenga la MAC*/

    /* Libero memoria */

    return NULL;
} /* -- send_lsu -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_hello_packet
 *
 * Gestiona los paquetes HELLO recibidos
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_hello_packet(struct sr_instance *sr, uint8_t *packet, unsigned int length, struct sr_if *rx_if)
{
    Debug("-> PWOSPF: Detecting PWOSPF HELLO Packet\n");
    /* Obtengo información del paquete recibido */
    ospfv2_hdr_t *rx_ospfv2_hdr = ((ospfv2_hdr_t *)(packet + ETHER_HDR_LENN + IP_HDR_LEN));
    ospfv2_hello_hdr_t *rx_ospfv2_hello_hdr = ((ospfv2_hello_hdr_t *)(packet + ETHER_HDR_LENN + IP_HDR_LEN + OSPF_HDR_LEN));
    /* Imprimo info del paquete recibido*/
    uint32_t neighbor_id = rx_ospfv2_hdr->rid;
    struct in_addr neighbor_id_addr;
    neighbor_id_addr.s_addr = neighbor_id;

    struct in_addr neighbor_ip;
    neighbor_ip.s_addr = rx_if->ip;

    struct in_addr net_mask;
    net_mask.s_addr = rx_ospfv2_hello_hdr->nmask;

    Debug("-> PWOSPF: Detecting PWOSPF HELLO Packet from:\n");
    Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id_addr));
    Debug("      [Neighbor IP = %s]\n", inet_ntoa(neighbor_ip));
    Debug("      [Network Mask = %s]\n", inet_ntoa(net_mask));

    /* Chequeo checksum */
    Debug("-> PWOSPF: Checking checksum\n");
    uint16_t packet_len_wo_eth_ip_hdrs;
    packet_len_wo_eth_ip_hdrs = length - ETHER_HDR_LENN - IP_HDR_LEN;
    uint16_t received_cksum = rx_ospfv2_hdr->csum;
    rx_ospfv2_hdr->csum = 0;
    uint16_t calculated_cksum = ospfv2_cksum(rx_ospfv2_hdr, packet_len_wo_eth_ip_hdrs);
    if (received_cksum != calculated_cksum)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid checksum\n");
        return;
    }
    Debug("-> PWOSPF: HELLO Packet checksum correct\n");

    /*Debug("-> PWOSPF: HELLO Packet dropped, invalid checksum\n");*/
    /* Chequeo de la máscara de red */
    /*Debug("-> PWOSPF: HELLO Packet dropped, invalid hello network mask\n");*/

    /* Chequeo del intervalo de HELLO */
    /*Debug("-> PWOSPF: HELLO Packet dropped, invalid hello interval\n");*/

    /* Seteo el vecino en la interfaz por donde llegó y actualizo la lista de vecinos */

    /* Si es un nuevo vecino, debo enviar LSUs por todas mis interfaces*/
    /* Recorro todas las interfaces para enviar el paquete LSU */
    /* Si la interfaz tiene un vecino, envío un LSU */

} /* -- sr_handle_pwospf_hello_packet -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_lsu_packet
 *
 * Gestiona los paquetes LSU recibidos y actualiza la tabla de topología
 * y ejecuta el algoritmo de Dijkstra
 *
 *---------------------------------------------------------------------*/

void *sr_handle_pwospf_lsu_packet(void *arg)
{
    powspf_rx_lsu_param_t *rx_lsu_param = ((powspf_rx_lsu_param_t *)(arg));

    /* Obtengo el vecino que me envió el LSU*/
    /* Imprimo info del paquete recibido*/
    /*
    Debug("-> PWOSPF: Detecting LSU Packet from [Neighbor ID = %s, IP = %s]\n", inet_ntoa(next_hop_id), inet_ntoa(next_hop_ip));
    */

    /* Chequeo checksum */
    /*Debug("-> PWOSPF: LSU Packet dropped, invalid checksum\n");*/

    /* Obtengo el Router ID del router originario del LSU y chequeo si no es mío*/
    /*Debug("-> PWOSPF: LSU Packet dropped, originated by this router\n");*/

    /* Obtengo el número de secuencia y uso check_sequence_number para ver si ya lo recibí desde ese vecino*/
    /*Debug("-> PWOSPF: LSU Packet dropped, repeated sequence number\n");*/

    /* Itero en los LSA que forman parte del LSU. Para cada uno, actualizo la topología.*/
    /*Debug("-> PWOSPF: Processing LSAs and updating topology table\n");*/
    /* Obtengo subnet */
    /* Obtengo vecino */
    /* Imprimo info de la entrada de la topología */
    /*
    Debug("      [Subnet = %s]", inet_ntoa(net_num));
    Debug("      [Mask = %s]", inet_ntoa(net_mask));
    Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));
    */
    /* LLamo a refresh_topology_entry*/

    /* Imprimo la topología */
    /*
    Debug("\n-> PWOSPF: Printing the topology table\n");
    print_topolgy_table(g_topology);
    */

    /* Ejecuto Dijkstra en un nuevo hilo (run_dijkstra)*/

    /* Flooding del LSU por todas las interfaces menos por donde me llegó */
    /* Seteo MAC de origen */
    /* Ajusto paquete IP, origen y checksum*/
    /* Ajusto cabezal OSPF: checksum y TTL*/
    /* Envío el paquete*/

    return NULL;
} /* -- sr_handle_pwospf_lsu_packet -- */

/**********************************************************************************
 * SU CÓDIGO DEBERÍA TERMINAR AQUÍ
 * *********************************************************************************/

/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_packet
 *
 * Gestiona los paquetes PWOSPF
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_packet(struct sr_instance *sr, uint8_t *packet, unsigned int length, struct sr_if *rx_if)
{
    /*Si aún no terminó la inicialización, se descarta el paquete recibido*/
    if (g_router_id.s_addr == 0)
    {
        return;
    }

    ospfv2_hdr_t *rx_ospfv2_hdr = ((ospfv2_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    powspf_rx_lsu_param_t *rx_lsu_param = ((powspf_rx_lsu_param_t *)(malloc(sizeof(powspf_rx_lsu_param_t))));

    Debug("-> PWOSPF: Detecting PWOSPF Packet\n");
    Debug("      [Type = %d]\n", rx_ospfv2_hdr->type);

    switch (rx_ospfv2_hdr->type)
    {
    case OSPF_TYPE_HELLO:
        sr_handle_pwospf_hello_packet(sr, packet, length, rx_if);
        break;
    case OSPF_TYPE_LSU:
        rx_lsu_param->sr = sr;
        unsigned int i;
        for (i = 0; i < length; i++)
        {
            rx_lsu_param->packet[i] = packet[i];
        }
        rx_lsu_param->length = length;
        rx_lsu_param->rx_if = rx_if;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_t pid;
        pthread_create(&pid, &attr, sr_handle_pwospf_lsu_packet, rx_lsu_param);
        break;
    }
} /* -- sr_handle_pwospf_packet -- */
