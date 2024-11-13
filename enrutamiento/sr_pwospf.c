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

#define OSPF_PROTOCOL_TYPE 89
#define OSPF_LSU_TIMEOUT 30

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

/*---------------------------------------------------------------------
 * Method: check_neighbors_life
 *
 * Chequea si los vecinos están vivos
 *
 *---------------------------------------------------------------------*/

void *check_neighbors_life(void *arg)
{
    Debug("\n-> PWOSPF: Neighbors life\n");
    struct sr_instance *sr = (struct sr_instance *)arg;

    while (1)
    {
        /* Se ejecuta cada 1 segundo */
        sleep(1);

        /* Bloqueo para acceder a estructuras compartidas */
        pwospf_lock(sr->ospf_subsys);

        int neighbor_changed = 0;

        /* Recorrer la lista de vecinos */
        struct ospfv2_neighbor *prev_neighbor = g_neighbors;
        struct ospfv2_neighbor *neighbor = g_neighbors->next;

        while (neighbor != NULL)
        {
            neighbor->alive += 1;

            if (neighbor->alive >= OSPF_NEIGHBOR_TIMEOUT)
            {
                /* El vecino ha superado el tiempo de espera, eliminarlo */
                Debug("-> PWOSPF: Neighbor %s timed out, removing from neighbor list\n", inet_ntoa(neighbor->neighbor_id));

                /* Actualizar el neighbor_id de la interfaz correspondiente */
                struct sr_if *iface = sr->if_list;
                while (iface != NULL)
                {
                    if (iface->neighbor_id == neighbor->neighbor_id.s_addr)
                    {
                        iface->neighbor_id = 0;
                        break;
                    }
                    iface = iface->next;
                }

                /* Eliminar el vecino de la lista */
                prev_neighbor->next = neighbor->next;
                free(neighbor);
                neighbor = prev_neighbor->next;

                neighbor_changed = 1;
            }
            else
            {
                prev_neighbor = neighbor;
                neighbor = neighbor->next;
            }
        }

        /* Si hubo cambios en la lista de vecinos, iniciar inundación de LSUs */
        if (neighbor_changed)
        {
            /* Recorro todas las interfaces para enviar el paquete LSU */
            struct sr_if *iface = sr->if_list;
            while (iface != NULL)
            {
                /* Si la interfaz tiene un vecino, envío un LSU */
                if (iface->neighbor_id != 0)
                {
                    powspf_hello_lsu_param_t *lsu_param = (powspf_hello_lsu_param_t *)malloc(sizeof(powspf_hello_lsu_param_t));
                    lsu_param->sr = sr;
                    lsu_param->interface = iface;

                    pthread_t lsu_thread;
                    pthread_create(&lsu_thread, NULL, send_lsu, lsu_param);
                    pthread_detach(lsu_thread);
                }
                iface = iface->next;
            }
        }

        /* Desbloquear */
        pwospf_unlock(sr->ospf_subsys);
    }

    return NULL;
} /* -- check_neighbors_life -- */

/*---------------------------------------------------------------------
 * Method: check_topology_entries_age
 *
 * Check if the topology entries are alive
 * and if they are not, remove them from the topology table
 *
 *---------------------------------------------------------------------*/

void* check_topology_entries_age(void* arg)
{
     Debug("\n-> PWOSPF: Check topology entries age\n");
    struct sr_instance* sr = (struct sr_instance*)arg;

    while (1)
    {
        /* Se ejecuta cada 1 segundo */
        sleep(1);

        /* Bloqueo para acceder a estructuras compartidas */
        pwospf_lock(sr->ospf_subsys);

        int topology_changed = 0;

        /* Recorrer la lista de entradas de topología */
        struct pwospf_topology_entry* prev_entry = g_topology;
        struct pwospf_topology_entry* entry = g_topology->next;

        while (entry != NULL)
        {
            entry->age += 1;

            if (entry->age >= OSPF_LSU_TIMEOUT)
            {
                /* La entrada ha superado el tiempo de vida, eliminarla */
                Debug("-> PWOSPF: Topology entry from Router ID %s expired, removing from topology\n",
                      inet_ntoa(entry->router_id));

                /* Eliminar la entrada de la topología */
                prev_entry->next = entry->next;
                free(entry);
                entry = prev_entry->next;

                topology_changed = 1;
            }
            else
            {
                prev_entry = entry;
                entry = entry->next;
            }
        }

        /* Si hubo cambios en la topología, ejecutar Dijkstra */
        if (topology_changed)
        {
            /* Imprimir la topología actualizada */
            Debug("\n-> PWOSPF: Printing the updated topology table\n");
            print_topolgy_table(g_topology);

            /* Ejecutar Dijkstra en un nuevo hilo */
            pthread_t dijkstra_thread;
            dijkstra_param_t* dijkstra_param = malloc(sizeof(dijkstra_param_t));
            dijkstra_param->sr = sr;
            dijkstra_param->topology = g_topology;
            dijkstra_param->rid = g_router_id;
            pthread_create(&dijkstra_thread, NULL, run_dijkstra, dijkstra_param);
            pthread_detach(dijkstra_thread);
        }

        /* Desbloquear */
        pwospf_unlock(sr->ospf_subsys);
    }

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
     Debug("\n-> PWOSPF: Send hellos\n");
    struct sr_instance *sr = (struct sr_instance *)arg;

    /* Mapa para almacenar el contador de HELLO por interfaz */
    struct sr_if *iface;
    int num_interfaces = 0;
    for (iface = sr->if_list; iface != NULL; iface = iface->next)
    {
        num_interfaces++;
    }

    /* Array para los contadores de las interfaces */
    int *hello_counters = (int *)malloc(sizeof(int) * num_interfaces);
    memset(hello_counters, 0, sizeof(int) * num_interfaces);

    while (1)
    {
        /* Se ejecuta cada 1 segundo */
        sleep(1);

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);

        /* Recorre todas las interfaces para enviar el paquete HELLO */
        int idx = 0;
        for (iface = sr->if_list; iface != NULL; iface = iface->next)
        {
            hello_counters[idx]++;

            if (hello_counters[idx] >= OSPF_DEFAULT_HELLOINT)
            {
                /* Crear los parámetros para send_hello_packet */
                powspf_hello_lsu_param_t *hello_param = malloc(sizeof(powspf_hello_lsu_param_t));
                hello_param->sr = sr;
                hello_param->interface = iface;

                /* Crear un hilo para enviar el paquete HELLO */
                pthread_t hello_thread;
                pthread_create(&hello_thread, NULL, send_hello_packet, hello_param);
                pthread_detach(hello_thread);

                /* Reiniciar el contador */
                hello_counters[idx] = 0;
            }

            idx++;
        }

        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
    }

    free(hello_counters);

    return NULL;
}
/* -- send_hellos -- */

/*---------------------------------------------------------------------
 * Method: send_hello_packet
 *
 * Recibe un mensaje HELLO, agrega cabezales y lo envía por la interfaz
 * correspondiente.
 *
 *---------------------------------------------------------------------*/

void *send_hello_packet(void *arg)
{
     Debug("\n-> PWOSPF: Send hello packet\n");
    powspf_hello_lsu_param_t *hello_param = (powspf_hello_lsu_param_t *)(arg);

    Debug("\n\nPWOSPF: Constructing HELLO packet for interface %s: \n", hello_param->interface->name);

    struct sr_instance *sr = hello_param->sr;
    struct sr_if *interface = hello_param->interface;

    /* Variables para almacenar el paquete y su longitud */
    uint8_t *packet;
    unsigned int packet_len;

    /* Variables para las longitudes de los encabezados */
    unsigned int eth_hdr_len = sizeof(sr_ethernet_hdr_t);
    unsigned int ip_hdr_len = sizeof(sr_ip_hdr_t);
    unsigned int ospf_hdr_len = sizeof(ospfv2_hdr_t);
    unsigned int ospf_hello_hdr_len = sizeof(ospfv2_hello_hdr_t);

    /* Calcular la longitud total del paquete */
    packet_len = eth_hdr_len + ip_hdr_len + ospf_hdr_len + ospf_hello_hdr_len;

    /* Alocar memoria para el paquete */
    packet = (uint8_t *)malloc(packet_len);
    if (!packet)
    {
        fprintf(stderr, "Failed to allocate memory for HELLO packet\n");
        return NULL;
    }
    memset(packet, 0, packet_len);

    /* Paso 1: Seteo la dirección MAC de multicast para la trama a enviar */
    /* Paso 2: Seteo la dirección MAC origen con la dirección de mi interfaz de salida */
    /* Paso 3: Seteo el ether_type en el cabezal Ethernet */

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    memcpy(eth_hdr->ether_dhost, g_ospf_multicast_mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    /* Paso 4: Inicializo cabezal IP */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + eth_hdr_len);
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = ip_hdr_len / 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(ip_hdr_len + ospf_hdr_len + ospf_hello_hdr_len);
    ip_hdr->ip_id = htons(0);
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = OSPF_PROTOCOL_TYPE;
    ip_hdr->ip_src = interface->ip;
    ip_hdr->ip_dst = htonl(OSPF_AllSPFRouters);

    /* Paso 5: Calculo y seteo el checksum IP */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);

    /* Paso 6: Inicializo cabezal de PWOSPF con versión 2 y tipo HELLO */
    ospfv2_hdr_t *ospf_hdr = (ospfv2_hdr_t *)(packet + eth_hdr_len + ip_hdr_len);
    ospf_hdr->version = OSPF_V2;
    ospf_hdr->type = OSPF_TYPE_HELLO;
    ospf_hdr->len = htons(ospf_hdr_len + ospf_hello_hdr_len);
    ospf_hdr->rid = g_router_id.s_addr;
    ospf_hdr->aid = htonl(0);
    ospf_hdr->csum = 0;
    ospf_hdr->autype = htons(0);
    ospf_hdr->audata = 0;

    /* Paso 7: Seteo máscara con la máscara de mi interfaz de salida */
    /* Paso 8: Seteo Hello Interval con OSPF_DEFAULT_HELLOINT */
    /* Paso 9: Seteo Padding en 0 */
    ospfv2_hello_hdr_t *ospf_hello_hdr = (ospfv2_hello_hdr_t *)(packet + eth_hdr_len + ip_hdr_len + ospf_hdr_len);
    ospf_hello_hdr->nmask = interface->mask;
    ospf_hello_hdr->helloint = htons(OSPF_DEFAULT_HELLOINT);
    ospf_hello_hdr->padding = 0;

    /* Paso 10: Calculo y actualizo el checksum del cabezal OSPF */
    ospf_hdr->csum = 0;
    uint16_t ospf_packet_len = ntohs(ospf_hdr->len);
    ospf_hdr->csum = cksum(ospf_hdr, ospf_packet_len);

    /* Paso 11: Envío el paquete HELLO */
    if (sr_send_packet(sr, packet, packet_len, interface->name) != 0)
    {
        fprintf(stderr, "Error sending HELLO packet\n");
    }
    else
    {
        /* Paso 12: Imprimo información del paquete HELLO enviado */
        Debug("-> PWOSPF: Sending HELLO Packet of length = %d, out of the interface: %s\n", packet_len, interface->name);
        Debug("      [Router ID = %s]\n", inet_ntoa(g_router_id));
        struct in_addr ip_addr;
        ip_addr.s_addr = interface->ip;
        Debug("      [Router IP = %s]\n", inet_ntoa(ip_addr));
        struct in_addr mask_addr;
        mask_addr.s_addr = interface->mask;
        Debug("      [Network Mask = %s]\n", inet_ntoa(mask_addr));
    }

    /* Liberar memoria */
    free(packet);

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
     Debug("\n-> PWOSPF: send all lsu\n");
    struct sr_instance *sr = (struct sr_instance *)arg;

    while (1)
    {
        /* Se ejecuta cada OSPF_DEFAULT_LSUINT segundos */
        sleep(OSPF_DEFAULT_LSUINT);

        /* Bloqueo para evitar conflictos */
        pwospf_lock(sr->ospf_subsys);

        struct sr_if *iface = sr->if_list;
        while (iface != NULL)
        {
            if (iface->neighbor_id != 0)
            {
                powspf_hello_lsu_param_t *lsu_param = malloc(sizeof(powspf_hello_lsu_param_t));
                lsu_param->sr = sr;
                lsu_param->interface = iface;

                pthread_t lsu_thread;
                pthread_create(&lsu_thread, NULL, send_lsu, lsu_param);
                pthread_detach(lsu_thread);
            }
            iface = iface->next;
        }

        pwospf_unlock(sr->ospf_subsys);
    }

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
     Debug("\n-> PWOSPF: Send lsu\n");
    powspf_hello_lsu_param_t *lsu_param = (powspf_hello_lsu_param_t *)(arg);
    struct sr_instance *sr = lsu_param->sr;
    struct sr_if *interface = lsu_param->interface;

    /* Paso 1: Solo envío LSUs si del otro lado hay un router */
    if (interface->neighbor_id == 0)
    {
        Debug("-> PWOSPF: No neighbor on interface %s, not sending LSU\n", interface->name);
        free(lsu_param);
        return NULL;
    }

    Debug("\n\nPWOSPF: Constructing LSU packet on interface %s\n", interface->name);

    /* Variables para almacenar el paquete y su longitud */
    uint8_t *packet;
    unsigned int packet_len;

    /* Variables para las longitudes de los encabezados */
    unsigned int eth_hdr_len = sizeof(sr_ethernet_hdr_t);
    unsigned int ip_hdr_len = sizeof(sr_ip_hdr_t);
    unsigned int ospf_hdr_len = sizeof(ospfv2_hdr_t);
    unsigned int ospf_lsu_hdr_len = sizeof(ospfv2_lsu_hdr_t);
    unsigned int lsa_len = sizeof(ospfv2_lsa_t);

    /* Paso 2: Contar el número de LSAs (rutas a enviar) */
    int num_lsas = 0;
    struct sr_rt *rt_entry = sr->routing_table;
    while (rt_entry != NULL)
    {
        /* Solo incluimos rutas directamente conectadas (interfaz misma o vecino) */
        if (strcmp(rt_entry->interface, interface->name) == 0)
        {
            num_lsas++;
        }
        rt_entry = rt_entry->next;
    }

    if (num_lsas == 0)
    {
        Debug("-> PWOSPF: No routes to advertise, not sending LSU\n");
        free(lsu_param);
        return NULL;
    }

    /* Paso 3: Calcular la longitud total del paquete */
    packet_len = eth_hdr_len + ip_hdr_len + ospf_hdr_len + ospf_lsu_hdr_len + (num_lsas * lsa_len);

    /* Alocar memoria para el paquete */
    packet = (uint8_t *)malloc(packet_len);
    if (!packet)
    {
        fprintf(stderr, "Failed to allocate memory for LSU packet\n");
        free(lsu_param);
        return NULL;
    }
    memset(packet, 0, packet_len);

    /* Paso 4: Inicializar el encabezado Ethernet */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    /* Dirección MAC de destino se completará después de obtenerla mediante ARP */
    eth_hdr->ether_type = htons(ethertype_ip);

    /* Paso 5: Inicializar el encabezado IP */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + eth_hdr_len);
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = ip_hdr_len / 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(ip_hdr_len + ospf_hdr_len + ospf_lsu_hdr_len + (num_lsas * lsa_len));
    ip_hdr->ip_id = htons(0);
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = OSPF_PROTOCOL_TYPE;
    ip_hdr->ip_src = interface->ip;
    /* IP de destino es la IP del vecino */
    struct in_addr neighbor_ip;
    neighbor_ip.s_addr = 0;
    /* Necesitamos obtener la IP del vecino usando su Router ID */
    struct sr_if *iface = sr->if_list;
    while (iface != NULL)
    {
        if (iface->neighbor_id == interface->neighbor_id)
        {
            neighbor_ip.s_addr = iface->ip & iface->mask;
            break;
        }
        iface = iface->next;
    }
    if (neighbor_ip.s_addr == 0)
    {
        Debug("-> PWOSPF: Unable to find neighbor IP, cannot send LSU\n");
        free(packet);
        free(lsu_param);
        return NULL;
    }
    ip_hdr->ip_dst = neighbor_ip.s_addr;

    /* Paso 6: Inicializar el encabezado OSPF */
    ospfv2_hdr_t *ospf_hdr = (ospfv2_hdr_t *)(packet + eth_hdr_len + ip_hdr_len);
    ospf_hdr->version = OSPF_V2;
    ospf_hdr->type = OSPF_TYPE_LSU;
    ospf_hdr->len = htons(ospf_hdr_len + ospf_lsu_hdr_len + (num_lsas * lsa_len));
    ospf_hdr->rid = g_router_id.s_addr;
    ospf_hdr->aid = htonl(0);
    ospf_hdr->csum = 0;
    ospf_hdr->autype = htons(0);
    ospf_hdr->audata = 0;

    /* Paso 7: Inicializar el encabezado LSU específico */
    ospfv2_lsu_hdr_t *lsu_hdr = (ospfv2_lsu_hdr_t *)(packet + eth_hdr_len + ip_hdr_len + ospf_hdr_len);
    lsu_hdr->seq = htons(++g_sequence_num);
    lsu_hdr->ttl = OSPF_MAX_LSU_TTL;
    lsu_hdr->unused = 0;
    lsu_hdr->num_adv = htonl(num_lsas);

    /* Paso 8: Agregar las LSAs al paquete */
    ospfv2_lsa_t *lsa = (ospfv2_lsa_t *)(packet + eth_hdr_len + ip_hdr_len + ospf_hdr_len + ospf_lsu_hdr_len);
    rt_entry = sr->routing_table;
    int lsa_index = 0;
    while (rt_entry != NULL && lsa_index < num_lsas)
    {
        if (strcmp(rt_entry->interface, interface->name) == 0)
        {
            lsa[lsa_index].subnet = rt_entry->dest.s_addr;
            lsa[lsa_index].mask = rt_entry->mask.s_addr;
            lsa[lsa_index].rid = interface->neighbor_id;
            lsa_index++;
        }
        rt_entry = rt_entry->next;
    }

    /* Paso 9: Calcular los checksums */
    /* Checksum del encabezado IP */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);

    /* Checksum del encabezado OSPF */
    ospf_hdr->csum = 0;
    uint16_t ospf_packet_len = ntohs(ospf_hdr->len);
    ospf_hdr->csum = cksum(ospf_hdr, ospf_packet_len);

    /* Paso 10: Obtener la dirección MAC del vecino mediante ARP */
    /* Dirección IP de destino */
    uint32_t next_hop_ip = ip_hdr->ip_dst;
    /* Buscar la dirección MAC en la caché ARP */
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    if (arp_entry)
    {
        /* MAC encontrada, completar el encabezado Ethernet */
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        free(arp_entry);

        /* Paso 11: Enviar el paquete */
        if (sr_send_packet(sr, packet, packet_len, interface->name) != 0)
        {
            fprintf(stderr, "Error sending LSU packet\n");
        }
        else
        {
            Debug("-> PWOSPF: Sent LSU Packet of length = %d, out of interface: %s\n", packet_len, interface->name);
            Debug("      [Router ID = %s]\n", inet_ntoa(g_router_id));
            Debug("      [Neighbor ID = %s]\n", inet_ntoa(*(struct in_addr *)&interface->neighbor_id));
        }
    }
    else
    {
        /* No se encontró en la caché ARP, enviar solicitud ARP */
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, packet_len, interface->name);
        handle_arpreq(sr, req);
        /* El paquete se almacenará y se enviará cuando se resuelva la dirección MAC */
        Debug("-> PWOSPF: LSU Packet queued, waiting for ARP resolution\n");
    }

    /* Paso 12: Liberar memoria */
    free(lsu_param);
    if (arp_entry == NULL)
    {
        /* No liberar packet, se liberará cuando se procese la respuesta ARP */
    }
    else
    {
        free(packet);
    }

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
    Debug("\n\nPWOSPF: Handling HELLO packet\n");
    /* Paso 1: Obtengo información del paquete recibido */

    /* Verificar que la longitud del paquete es suficiente */
    unsigned int eth_hdr_len = sizeof(sr_ethernet_hdr_t);
    unsigned int ip_hdr_len = sizeof(sr_ip_hdr_t);
    unsigned int ospf_hdr_len = sizeof(ospfv2_hdr_t);
    unsigned int ospf_hello_hdr_len = sizeof(ospfv2_hello_hdr_t);

    if (length < eth_hdr_len + ip_hdr_len + ospf_hdr_len + ospf_hello_hdr_len)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, insufficient length\n");
        return;
    }

    /* Extraer los encabezados */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + eth_hdr_len);
    ospfv2_hdr_t *ospf_hdr = (ospfv2_hdr_t *)(packet + eth_hdr_len + ip_hdr_len);
    ospfv2_hello_hdr_t *ospf_hello_hdr = (ospfv2_hello_hdr_t *)(packet + eth_hdr_len + ip_hdr_len + ospf_hdr_len);

    /* Paso 2: Imprimo info del paquete recibido */
    struct in_addr neighbor_id;
    neighbor_id.s_addr = ospf_hdr->rid;
    struct in_addr neighbor_ip;
    neighbor_ip.s_addr = ip_hdr->ip_src;
    struct in_addr net_mask;
    net_mask.s_addr = ospf_hello_hdr->nmask;

    Debug("-> PWOSPF: Detecting PWOSPF HELLO Packet from:\n");
    Debug("      [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));
    Debug("      [Neighbor IP = %s]\n", inet_ntoa(neighbor_ip));
    Debug("      [Network Mask = %s]\n", inet_ntoa(net_mask));

    /* Paso 3: Chequeo checksum */

    /* Verificar el checksum del encabezado OSPF */
    uint16_t received_checksum = ospf_hdr->csum;
    ospf_hdr->csum = 0;
    uint16_t calculated_checksum = cksum(ospf_hdr, ntohs(ospf_hdr->len));

    if (received_checksum != calculated_checksum)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid checksum\n");
        return;
    }
    ospf_hdr->csum = received_checksum;

    /* Paso 4: Chequeo de la máscara de red */
    if (ospf_hello_hdr->nmask != rx_if->mask)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello network mask\n");
        return;
    }

    /* Paso 5: Chequeo del intervalo de HELLO */
    if (ntohs(ospf_hello_hdr->helloint) != OSPF_DEFAULT_HELLOINT)
    {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello interval\n");
        return;
    }

    /* Paso 6: Seteo el vecino en la interfaz por donde llegó y actualizo la lista de vecinos */

    pwospf_lock(sr->ospf_subsys);

    /* Actualizar el neighbor_id en la interfaz */
    rx_if->neighbor_id = neighbor_id.s_addr;

    /* Actualizar la lista de vecinos */
    struct ospfv2_neighbor *neighbor = g_neighbors->next;
    int neighbor_found = 0;
    while (neighbor != NULL)
    {
        if (neighbor->neighbor_id.s_addr == neighbor_id.s_addr)
        {
            /* Vecino conocido, reiniciar el contador de tiempo */
            neighbor->alive = 0;
            neighbor_found = 1;
            break;
        }
        neighbor = neighbor->next;
    }

    if (!neighbor_found)
    {
        /* Nuevo vecino, agregar a la lista */
        struct ospfv2_neighbor *new_neighbor = create_ospfv2_neighbor(neighbor_id);
        new_neighbor->alive = 0;
        add_neighbor(g_neighbors, new_neighbor);
        Debug("-> PWOSPF: New neighbor detected, adding to neighbor list\n");
    }

    pwospf_unlock(sr->ospf_subsys);

    /* Paso 7: Si es un nuevo vecino, debo enviar LSUs por todas mis interfaces */

    if (!neighbor_found)
    {
        /* Recorro todas las interfaces para enviar el paquete LSU */
        struct sr_if *iface = sr->if_list;
        while (iface != NULL)
        {
            /* Si la interfaz tiene un vecino, envío un LSU */
            if (iface->neighbor_id != 0)
            {
                powspf_hello_lsu_param_t *lsu_param = (powspf_hello_lsu_param_t *)malloc(sizeof(powspf_hello_lsu_param_t));
                lsu_param->sr = sr;
                lsu_param->interface = iface;

                pthread_t lsu_thread;
                pthread_create(&lsu_thread, NULL, send_lsu, lsu_param);
                pthread_detach(lsu_thread);
            }
            iface = iface->next;
        }
    }

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
    Debug("\n\nPWOSPF: Handling LSU packet\n");
    powspf_rx_lsu_param_t *rx_lsu_param = (powspf_rx_lsu_param_t *)(arg);
    struct sr_instance *sr = rx_lsu_param->sr;
    uint8_t *packet = rx_lsu_param->packet;
    unsigned int length = rx_lsu_param->length;
    struct sr_if *rx_if = rx_lsu_param->rx_if;

    /* Paso 1: Extraer los encabezados y verificar la longitud del paquete */
    unsigned int eth_hdr_len = sizeof(sr_ethernet_hdr_t);
    unsigned int ip_hdr_len = sizeof(sr_ip_hdr_t);
    unsigned int ospf_hdr_len = sizeof(ospfv2_hdr_t);
    unsigned int ospf_lsu_hdr_len = sizeof(ospfv2_lsu_hdr_t);
    unsigned int lsa_len = sizeof(ospfv2_lsa_t);

    if (length < eth_hdr_len + ip_hdr_len + ospf_hdr_len + ospf_lsu_hdr_len)
    {
        Debug("-> PWOSPF: LSU Packet dropped, insufficient length\n");
        free(rx_lsu_param);
        return NULL;
    }

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + eth_hdr_len);
    ospfv2_hdr_t *ospf_hdr = (ospfv2_hdr_t *)(packet + eth_hdr_len + ip_hdr_len);
    ospfv2_lsu_hdr_t *lsu_hdr = (ospfv2_lsu_hdr_t *)(packet + eth_hdr_len + ip_hdr_len + ospf_hdr_len);
    ospfv2_lsa_t *lsa = (ospfv2_lsa_t *)(packet + eth_hdr_len + ip_hdr_len + ospf_hdr_len + ospf_lsu_hdr_len);

    /* Paso 2: Verificar el checksum del encabezado OSPF */
    uint16_t received_checksum = ospf_hdr->csum;
    ospf_hdr->csum = 0;
    uint16_t calculated_checksum = cksum(ospf_hdr, ntohs(ospf_hdr->len));
    if (received_checksum != calculated_checksum)
    {
        Debug("-> PWOSPF: LSU Packet dropped, invalid checksum\n");
        free(rx_lsu_param);
        return NULL;
    }
    ospf_hdr->csum = received_checksum;

    /* Paso 3: Verificar si el LSU fue originado por este router */
    if (ospf_hdr->rid == g_router_id.s_addr)
    {
        Debug("-> PWOSPF: LSU Packet dropped, originated by this router\n");
        free(rx_lsu_param);
        return NULL;
    }

    /* Paso 4: Verificar el número de secuencia */
    uint16_t seq_num = ntohs(lsu_hdr->seq);
    struct in_addr sender_rid;
    sender_rid.s_addr = ospf_hdr->rid;
    if (check_sequence_number(g_topology, sender_rid, seq_num) == 0)
    {
        Debug("-> PWOSPF: LSU Packet dropped, repeated sequence number\n");
        free(rx_lsu_param);
        return NULL;
    }

    /* Paso 5: Procesar cada LSA en el LSU */
    uint32_t num_lsas = ntohl(lsu_hdr->num_adv);
    if (length < eth_hdr_len + ip_hdr_len + ospf_hdr_len + ospf_lsu_hdr_len + (num_lsas * lsa_len))
    {
        Debug("-> PWOSPF: LSU Packet dropped, insufficient length for LSAs\n");
        free(rx_lsu_param);
        return NULL;
    }

    Debug("-> PWOSPF: Processing LSAs and updating topology table\n");

    pwospf_lock(sr->ospf_subsys);

    int topology_changed = 0;
    uint32_t i;
    for (i = 0; i < num_lsas; i++)
    {
        struct in_addr net_num, net_mask, neighbor_id;
        net_num.s_addr = lsa[i].subnet;
        net_mask.s_addr = lsa[i].mask;
        neighbor_id.s_addr = lsa[i].rid;

        Debug("      [Subnet = %s]", inet_ntoa(net_num));
        Debug(" [Mask = %s]", inet_ntoa(net_mask));
        Debug(" [Neighbor ID = %s]\n", inet_ntoa(neighbor_id));

        /* Actualizar la topología */
        struct in_addr x;
        x.s_addr = rx_if->ip;

        refresh_topology_entry(g_topology, sender_rid, net_num, net_mask, neighbor_id, x, seq_num);
        topology_changed = 1;
    }

    pwospf_unlock(sr->ospf_subsys);

    /* Paso 6: Imprimir la topología */
    Debug("\n-> PWOSPF: Printing the topology table\n");
    print_topolgy_table(g_topology);

    /* Paso 7: Ejecutar Dijkstra si la topología ha cambiado */
    if (topology_changed)
    {
        pthread_t dijkstra_thread;
        dijkstra_param_t *dijkstra_param = malloc(sizeof(dijkstra_param_t));
        dijkstra_param->sr = sr;
        dijkstra_param->topology = g_topology;
        dijkstra_param->rid = g_router_id;
        pthread_create(&dijkstra_thread, NULL, run_dijkstra, dijkstra_param);
        pthread_detach(dijkstra_thread);
    }

    /* Paso 8: Reenviar el LSU a otros vecinos (flooding) */
    lsu_hdr->ttl -= 1;
    if (lsu_hdr->ttl > 0)
    {
        /* Recalcular checksum OSPF */
        ospf_hdr->csum = 0;
        ospf_hdr->csum = cksum(ospf_hdr, ntohs(ospf_hdr->len));

        /* Recalcular checksum IP */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

        /* Enviar el LSU por todas las interfaces excepto por donde llegó */
        struct sr_if *iface = sr->if_list;
        while (iface != NULL)
        {
            if (strcmp(iface->name, rx_if->name) != 0 && iface->neighbor_id != 0)
            {
                /* Obtener la dirección MAC del vecino */
                uint32_t next_hop_ip = iface->ip & iface->mask;
                struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
                if (arp_entry)
                {
                    /* Actualizar encabezado Ethernet */
                    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
                    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

                    /* Enviar el paquete */
                    if (sr_send_packet(sr, packet, length, iface->name) != 0)
                    {
                        fprintf(stderr, "Error forwarding LSU packet\n");
                    }
                    else
                    {
                        Debug("-> PWOSPF: Forwarded LSU Packet out of interface: %s\n", iface->name);
                    }

                    free(arp_entry);
                }
                else
                {
                    /* Encolar para ARP */
                    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, length, iface->name);
                    handle_arpreq(sr, req);
                }
            }
            iface = iface->next;
        }
    }

    /* Paso 9: Liberar memoria */
    free(rx_lsu_param);
    free(packet);

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
