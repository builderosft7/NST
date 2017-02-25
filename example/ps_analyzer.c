#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <getopt.h>
#define getopt getopt____
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>

#include "../config.h"

#ifdef HAVE_JSON_C
#include <json.h>
#endif

#include "ndpi_api.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_NUM_READER_THREADS     16

/**
 * @brief Set main components necessary to the detection
 * @details TODO
 */
static void setupDetection(u_int16_t thread_id);

/**
 * Client parameters
 */
static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interafaces */
static char *output_dir = NULL;
static int packets_per_file = 0;
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
static char *_bpf_filter      = NULL; /**< bpf filter  */
static char *_url_stat        = NULL; //file of url filters 
static char *_protoFilePath   = NULL; /**< Protocol file path  */
#ifdef HAVE_JSON_C
static char *_jsonFilePath    = NULL; /**< JSON file path  */
#endif
#ifdef HAVE_JSON_C
static json_object *jArray_known_flows, *jArray_unknown_flows;
#endif
static u_int8_t live_capture = 0;
static u_int8_t undetected_flows_deleted = 0;
/**
 * User preferences
 */
static u_int8_t enable_protocol_guess = 1, verbose = 0, nDPI_traceLevel = 0, json_flag = 0;
static u_int16_t decode_tunnels = 0;
static u_int16_t create_ip_list = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0;
static u_int8_t num_threads = 1;
static u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
#ifdef linux
static int core_affinity[MAX_NUM_READER_THREADS];
static int VLAN_LEVEL_ARR[5] = { 0 };		//CHECK IF NEEDED
static int MPLS_LEVEL_ARR[5] = { 0 };		//CHECK IF NEEDED
static int num_of_duplicated_pckts = 0;		//CHECK IF NEEDED
static int num_of_single_side = 0;			//CHECK IF NEEDED
static int ETHER_TYPE_ARR[65536] = { 0 };	//CHECK IF NEEDED
static int NEW_CONNECTIONS_ARR[10000] = { 0 };	//CHECK IF NEEDED
static int TCP_CONNECTIONS_ARR[10000] = { 0 };	//CHECK IF NEEDED
static int UDP_CONNECTIONS_ARR[10000] = { 0 };	//CHECK IF NEEDED
static int HTTP_CONNECTIONS_ARR[10000] = { 0 };	//CHECK IF NEEDED
static int SSL_CONNECTIONS_ARR[10000] = { 0 };	//CHECK IF NEEDED
static int total_tcp_flows = 0;
static int total_udp_flows = 0;
static int total_http_flows = 0;
static int total_ssl_flows = 0;
static int single_side_flow_count = 0;
static int tcp_connection_size_packets = 0;
static int udp_connection_size_packets = 0;
static int http_connection_size_packets = 0;
static int ssl_connection_size_packets = 0;
static int flows_with_get = 0, flows_with_post = 0, flows_with_head = 0;
float tcp_connection_size_bytes = 0;
float udp_connection_size_bytes = 0;
float http_connection_size_bytes = 0;
float ssl_connection_size_bytes = 0;
float total_flows;
float total_packets;
float total_bytes;
float tcp_connection_duration = 0;
float udp_connection_duration = 0;
float http_connection_duration = 0;
float ssl_connection_duration = 0;
float tot_eth_gbits_per_sec = 0;
float traffic_duration_all = 0;
int traffic_duration_all_sec = 0;
int rule_dup = 0;							//CHECK IF NEEDED
int rule_sing = 0;							//CHECK IF NEEDED
static int ipv6_counter = 0;				//CHECK IF NEEDED
#endif
/*
 * Create Results Directory in /tmp
 * */
FILE *f_connection;
FILE *f_sip_ip_list;
FILE *f_sip_couple_list;
FILE *f_ips_list;
FILE *f_general;
FILE *f_http;
FILE *f_sip;
FILE *f_sig;
FILE *f_sip_codecs;
FILE *f_sip_content_type;
FILE *f_persecnewflow;
FILE *f_protocols;
FILE *f_per_sip_peer;



struct timeval begin_of_traffic;
u_int64_t analysis_start_time = 0;
u_int64_t analysis_start_time_usec = 0;
u_int64_t last_flowendtime = 0;
u_int64_t last_flowendtime_sec = 0;
u_int64_t ssl_cert_counter = 0;
u_int64_t ssl_sni_counter = 0;



static struct timeval pcap_start, pcap_end;

/**
 * Detection parameters
 */
static u_int32_t detection_tick_resolution = 1000;
static time_t capture_for = 0;
static time_t capture_until = 0;

#define IDLE_SCAN_PERIOD           10 /* msec (use detection_tick_resolution = 1000) */
#define MAX_IDLE_TIME           30000
#define IDLE_SCAN_BUDGET         1024

#define NUM_ROOTS                 512

static u_int32_t num_flows;

struct thread_stats {
  u_int32_t guessed_flow_protocols;
  u_int64_t raw_packet_count;
  u_int64_t ip_packet_count;
  u_int64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
  u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t ndpi_flow_count;
  u_int64_t http_avg_get_size, http_avg_post_size, http_avg_head_size, http_get_count, http_post_count, http_head_count, tcp_count, udp_count, sccp_count, isup_count, bicc_count, h248_count, sip_ack_count, sip_bye_count, sip_options_count, sip_invite_count, sip_cancel_count, sip_prack_count, dup_flows, udp_frag, tcp_frag, dup_http_flows, dup_ssl_flows;
  u_int64_t mpls_count, mpls_level_count[5], pppoe_count, vlan_count, fragmented_count, vlan_ids_count[4096], vlan_level_count[4];
  u_int64_t packet_len[6];
  u_int16_t max_packet_len;
};

struct reader_thread {
  struct ndpi_detection_module_struct *ndpi_struct;
  void *ndpi_flows_root[NUM_ROOTS];
  char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *_pcap_handle;
  u_int64_t last_time;
  u_int64_t last_idle_scan_time;
  u_int32_t idle_scan_idx;
  u_int32_t num_idle_flows;
  pthread_t pthread;
  int _pcap_datalink_type;

  /* TODO Add barrier */
  struct thread_stats stats;

  struct ndpi_flow *idle_flows[IDLE_SCAN_BUDGET];
};

static struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];

#define GTP_U_V1_PORT        2152
#define MAX_NDPI_FLOWS  200000000
/**
 * @brief ID tracking
 */
typedef struct ndpi_id {
  u_int8_t ip[4];                               //< Ip address
  struct ndpi_id_struct *ndpi_id;               //< nDpi worker structure
} ndpi_id_t;

static u_int32_t size_id_struct = 0;            //< ID tracking structure size
//static u_int16_t is_check_dup[MAX_NUM_READER_THREADS] = {0};  //Not in use
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

// flow tracking
typedef struct ndpi_flow {  
  u_int32_t left_side_ip;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol, is_dup, not_single_side, get_in_flow, post_in_flow, head_in_flow;
  u_int16_t vlan_id , syn_ip_id;
  u_int16_t __padding;						//CHECK IF NEEDED
  struct ndpi_flow_struct *ndpi_flow;
  char lower_name[32], upper_name[32];

  u_int64_t last_seen;
  u_int64_t bytes;
  u_int32_t packets;

  // result only, not used for flow identification
  u_int32_t detected_protocol, total_sip_invite_inflow, total_sip_200_ok_inflow;

  char host_server_name[256];
  u_char dup_mac_addresses[4][6];
  
  struct {
    char client_certificate[48], server_certificate[48];
  } ssl;

  void *src_id, *dst_id;

  //Flow Start and End time
  struct timeval start_time;
  struct timeval end_time;

  //Flow capture file
  pcap_dumper_t *flow_file;
  pcap_t *pd;

} ndpi_flow_t;


static u_int32_t size_flow_struct = 0;

static void help(u_int long_help) {
  printf("ps_analyzer -i <file|device> [-f <filter>][-s <duration>]\n"
         "          [-p <protos>][-l <loops>[-d][-h][-t][-v <level>]\n"
         "          [-n <threads>] [-j <file>]\n\n"
         "Usage:\n"
         "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a device for live capture (comma-separated list)\n"
		 "  -o <directory>            | Specify a directory to create pcap dump per flow. (example - /root/files/)\n"
     	 "  -w <number of packets>    | Number of packets per pcap dump file\n"
         "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
         "  -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n"
         "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
         "  -l <num loops>            | Number of detection loops (test only)\n"
         "  -n <num threads>          | Number of threads. Default: number of interfaces in -i. Ignored with pcap files.\n"
         "  -j <file.json>            | Specify a file to write the content of packets in .json format\n"
#ifdef linux
         "  -g <id:id...>             | Thread affinity mask (one core id per thread)\n"
#endif
         "  -d                        | Disable protocol guess and use only DPI\n"
         "  -t                        | Dissect GTP tunnels\n"
         "  -h                        | This help\n"
	     "  -u <url filters>          | MB of traffic per url filter\n"
         "  -v <1|2>                  | Verbose 'unknown protocol' packet print. 1=verbose, 2=very verbose\n"
         "  -V <1|2>                  | Verbose ps_analyzer trace log print. 1=trace, 2=debug\n");

  if(long_help) {
    printf("\n\nSupported protocols:\n");
    num_threads = 1;
    setupDetection(0);
    ndpi_dump_protocols(ndpi_thread_info[0].ndpi_struct);
  }

  exit(!long_help);
}

/* ***************************************************** */

static void parseOptions(int argc, char **argv) {
  char *__pcap_file = NULL, *bind_mask = NULL;
  int thread_id, opt;
#ifdef linux
  u_int num_cores = sysconf( _SC_NPROCESSORS_ONLN );
#endif


  while ((opt = getopt(argc, argv, "df:g:i:o:w:hp:l:s:tv:IV:n:j:u:")) != EOF) {
    switch (opt) {
    case 'd':
      enable_protocol_guess = 0;
      break;

    case 'i':
      _pcap_file[0] = optarg;
      break;

	case 'w':
    	packets_per_file = atoi(optarg);
       break;

    case 'o':
    	output_dir = optarg;
      break;

    case 'f':
      _bpf_filter = optarg;
      break;

    case 'g':
      bind_mask = optarg;
      break;

    case 'l':
      num_loops = atoi(optarg);
      break;

    case 'n':
      num_threads = atoi(optarg);
      break;

    case 'p':
      _protoFilePath = optarg;
      break;

    case 's':
      capture_for = atoi(optarg);
      capture_until = capture_for + time(NULL);
      break;

    case 't':
      decode_tunnels = 1;
      break;

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'I':
      create_ip_list = 1;
      break;

    case 'V':
      printf("%d\n",atoi(optarg) );
      nDPI_traceLevel  = atoi(optarg);
      break;

    case 'h':
      help(1);
      break;

    case 'j':
#ifndef HAVE_JSON_C
      printf("WARNING: this copy of ps_analyzer has been compiled without JSON-C: json export disabled\n");
#else
      _jsonFilePath = optarg;
      json_flag = 1;
#endif
      break;
      
    case 'u':
        _url_stat = optarg; 
        break;
    default:
      help(0);
      break;
    }
  }

  // check parameters
  if(_pcap_file[0] == NULL || strcmp(_pcap_file[0], "") == 0) {
    help(0);
  }

  if(strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
    num_threads = 0; /* setting number of threads = number of interfaces */
    __pcap_file = strtok(_pcap_file[0], ",");
    while (__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
      _pcap_file[num_threads++] = __pcap_file;
      __pcap_file = strtok(NULL, ",");
    }
  } else {
    if(num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
    for(thread_id = 1; thread_id < num_threads; thread_id++)
      _pcap_file[thread_id] = _pcap_file[0];
  }

#ifdef linux
  for(thread_id = 0; thread_id < num_threads; thread_id++)
    core_affinity[thread_id] = -1;

  if(num_cores > 1 && bind_mask != NULL) {
    char *core_id = strtok(bind_mask, ":");
    thread_id = 0;
    while (core_id != NULL && thread_id < num_threads) {
      core_affinity[thread_id++] = atoi(core_id) % num_cores;
      core_id = strtok(NULL, ":");
    }
  }
#endif
}

/* ***************************************************** */

static void debug_printf(u_int32_t protocol, void *id_struct,
                         ndpi_log_level_t log_level,
                         const char *format, ...) {
  va_list va_ap;
#ifndef WIN32
  struct tm result;
#endif

  if(log_level <= nDPI_traceLevel) {
    char buf[8192], out_buf[8192];
    char theDate[32];
    const char *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    if(log_level == NDPI_LOG_ERROR)
      extra_msg = "ERROR: ";
    else if(log_level == NDPI_LOG_TRACE)
      extra_msg = "TRACE: ";
    else
      extra_msg = "DEBUG: ";

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime,&result) );
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
    printf("%s", out_buf);
    fflush(stdout);
  }

  va_end(va_ap);
}

/* ***************************************************** */

static void *malloc_wrapper(unsigned long size) {
  current_ndpi_memory += size;

  if(current_ndpi_memory > max_ndpi_memory)
    max_ndpi_memory = current_ndpi_memory;

  return malloc(size);
}

/* ***************************************************** */

static void free_wrapper(void *freeable) {
  free(freeable);
}

/* ***************************************************** */

static char* ipProto2Name(u_short proto_id) {
  static char proto[8];

  switch(proto_id) {
  case IPPROTO_TCP:
    return("TCP");
    break;
  case IPPROTO_UDP:
    return("UDP");
    break;
  case IPPROTO_ICMP:
    return("ICMP");
    break;
  case 112:
    return("VRRP");
    break;
  case IPPROTO_IGMP:
    return("IGMP");
    break;
  }

  snprintf(proto, sizeof(proto), "%u", proto_id);
  return(proto);
}

/* ***************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  uint byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
        *--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ***************************************************** */
/*
 void printMacAddresses(u_char* source_mac, u_char* dest_mac)
{
    printf("src: [%hhx:%hhx:%x:%x:%x:%x] dest: [%x:%x:%x:%x:%x:%x] ",source_mac[0], source_mac[1], source_mac[2]
            ,source_mac[3], source_mac[4],source_mac[5], dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3]
            ,dest_mac[4], dest_mac[5]);
}
*/


/* ***************************************************** */
static void finalFlowResults(u_int16_t thread_id, struct ndpi_flow *flow) {
#ifdef HAVE_JSON_C
  json_object *jObj;
#endif
  if(!json_flag) {
	float traffic_duration;
	long long unsigned int flowstarttime;
	long long unsigned int flowendtime;
	long long unsigned int normal_flowstarttime;
	long long unsigned int normal_flowendtime;


    traffic_duration = (flow->end_time.tv_sec*1000000 + flow->end_time.tv_usec) - (flow->start_time.tv_sec*1000000 + flow->start_time.tv_usec);
    traffic_duration = traffic_duration/1000000;
    if(traffic_duration !=0 )
      {
      	float bit_rate = ((flow->bytes*8)/traffic_duration) ;
      	float packets_rate = (flow->packets/traffic_duration);
//      	printf(" Packets/Sec:%.3f  Bits/Sec:%.3f Duration(sec):%.3f", packets_rate, bit_rate, traffic_duration);
      }

/*
    printf(" Traffic start time: %llu ",  analysis_start_time);
    flowstarttime = flow->start_time.tv_sec;
    flowendtime = flow->end_time.tv_sec;
    normal_flowstarttime = flowstarttime - analysis_start_time;
    normal_flowendtime = flowendtime - analysis_start_time;
    printf(" FlowETime: %llu FlowSTime: %llu FlowASTime: %llu FlowAETime: %llu",  flowendtime, flowstarttime, normal_flowstarttime, normal_flowendtime );
*/

	float connection_duration;
    	connection_duration = (flow->end_time.tv_sec*1000000 + flow->end_time.tv_usec) - (flow->start_time.tv_sec*1000000 + flow->start_time.tv_usec);
    	connection_duration = (float)connection_duration/1000000;
      	float connection_size_bytes = flow->bytes;
      	float connection_size_packets = flow->packets;

        if(flow->protocol == IPPROTO_TCP) {
  		if(ntohs(flow->upper_port) == 80 || ntohs(flow->lower_port) == 80)
  		{     //I will count all port 80 as HTTP traffic
		    http_connection_duration+=connection_duration;
		    http_connection_size_bytes+=connection_size_bytes;
		    http_connection_size_packets+=connection_size_packets;
	    	
  		}
  		if(ntohs(flow->upper_port) == 443 || ntohs(flow->lower_port) == 443)
  		{     //I will count all port 443 as SSL traffic
		 	ssl_connection_duration+=connection_duration;
		   	ssl_connection_size_bytes+=connection_size_bytes;
		    	ssl_connection_size_packets+=connection_size_packets;
//    			if(flow->host_server_name[0] != '\0') printf("[Host: %s]\n", flow->host_server_name);
//    			if(flow->ssl.client_certificate[0] != '\0') printf("[SSL client: %s]\n", flow->ssl.client_certificate);
//    			if(flow->ssl.server_certificate[0] != '\0') printf("[SSL server: %s]\n", flow->ssl.server_certificate);
	  	}
	    	tcp_connection_duration+=connection_duration;
	    	tcp_connection_size_bytes+=connection_size_bytes;
	    	tcp_connection_size_packets+=connection_size_packets;
    		if((flow->ssl.client_certificate[0] != '\0')) ssl_sni_counter++;
    		if((flow->ssl.server_certificate[0] != '\0')||(flow->ssl.client_certificate[0] != '\0')) ssl_cert_counter++;
        }

        if(flow->protocol == IPPROTO_UDP) {
	    udp_connection_duration+=connection_duration;
	    udp_connection_size_bytes+=connection_size_bytes;
	    udp_connection_size_packets+=connection_size_packets;
        }





  } else {
#ifdef HAVE_JSON_C
    jObj = json_object_new_object();

    json_object_object_add(jObj,"protocol",json_object_new_string(ipProto2Name(flow->protocol)));
    json_object_object_add(jObj,"host_a.name",json_object_new_string(flow->lower_name));
    json_object_object_add(jObj,"host_a.port",json_object_new_int(ntohs(flow->lower_port)));
    json_object_object_add(jObj,"host_b.name",json_object_new_string(flow->upper_name));
    json_object_object_add(jObj,"host_n.port",json_object_new_int(ntohs(flow->upper_port)));
    json_object_object_add(jObj,"detected.protocol",json_object_new_int(flow->detected_protocol));
    json_object_object_add(jObj,"detected.protocol.name",json_object_new_string(ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol)));
    json_object_object_add(jObj,"packets",json_object_new_int(flow->packets));
    json_object_object_add(jObj,"bytes",json_object_new_int(flow->bytes));

    if(flow->host_server_name[0] != '\0')
      json_object_object_add(jObj,"host.server.name",json_object_new_string(flow->host_server_name));

    if((flow->ssl.client_certificate[0] != '\0') || (flow->ssl.server_certificate[0] != '\0')) {
      json_object *sjObj = json_object_new_object();

      if(flow->ssl.client_certificate[0] != '\0')
        json_object_object_add(sjObj, "client", json_object_new_string(flow->ssl.client_certificate));

      if(flow->ssl.server_certificate[0] != '\0')
        json_object_object_add(sjObj, "server", json_object_new_string(flow->ssl.server_certificate));

      json_object_object_add(jObj, "ssl", sjObj);
    }

    //flow->protos.ssl.client_certificate, flow->protos.ssl.server_certificate);
    if(json_flag == 1)
      json_object_array_add(jArray_known_flows,jObj);
    else if(json_flag == 2)
      json_object_array_add(jArray_unknown_flows,jObj);
#endif
  }
}



/* ***************************************************** */
static void printFlow(u_int16_t thread_id, struct ndpi_flow *flow) {
#ifdef HAVE_JSON_C
  json_object *jObj;
#endif

  if(!json_flag) {
#if 0
    printf("\t%s [VLAN: %u] %s:%u <-> %s:%u\n",
	   ipProto2Name(flow->protocol), flow->vlan_id,
	   flow->lower_name, ntohs(flow->lower_port),
	   flow->upper_name, ntohs(flow->upper_port));

#else
    if (flow->detected_protocol == 100 || flow->detected_protocol == 87|| flow->detected_protocol == 187) 
        {
    	//fprintf(f_ips, "Repeatitions,L4Protocol,IP1,port1,IP2,port2,Vlan,Protocol #,Protocol Name,Packets,Bytes\n");
    	fprintf(f_connection, "%s ,%s,%hu,%s,%hu,%u,%u,%s,%u,%llu\n" ,
		ipProto2Name(flow->protocol),
		flow->lower_name,ntohs(flow->lower_port),
		flow->upper_name,ntohs(flow->upper_port),
		flow->vlan_id, flow->detected_protocol, 
		ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct,flow->detected_protocol), 
		flow->packets,(long long unsigned int)flow->bytes);
    	fprintf(f_sip_ip_list, "%s,%s\n%s,%s\n" ,
		ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct,flow->detected_protocol), 
		flow->lower_name,
		ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct,flow->detected_protocol), 
		flow->upper_name);
    	fprintf(f_sip_couple_list, "%s,%s,%s\n" ,
		ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct,flow->detected_protocol), 
		flow->lower_name,
		flow->upper_name);
        }
    if (create_ip_list)
    	fprintf(f_ips_list, "%s\n%s\n" ,flow->lower_name,flow->upper_name);
      
  /*  printf("\t%u", ++num_flows);
  /*  printf("\t%u", ++num_flows);

    printf("\t%s %s:%hu <-> %s:%hu ",
	   ipProto2Name(flow->protocol),
	   flow->lower_name, ntohs(flow->lower_port),
	   flow->upper_name, ntohs(flow->upper_port));

    printf("[VLAN: %u][proto: %u/%s][%u pkts/%llu bytes]",
	   flow->vlan_id, flow->detected_protocol,
	   ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol),
	   flow->packets, (long long unsigned int)flow->bytes);

    if(flow->host_server_name[0] != '\0') printf("[Host: %s]", flow->host_server_name);
    if(flow->ssl.client_certificate[0] != '\0') printf("[SSL client: %s]", flow->ssl.client_certificate);
    if(flow->ssl.server_certificate[0] != '\0') printf("[SSL server: %s]", flow->ssl.server_certificate);
   *//* if(flow->is_dup)
    {
        printf("[Has Duplication] ");
        printMacAddresses(flow->dup_mac_addresses[0],flow->dup_mac_addresses[1]);
        printMacAddresses(flow->dup_mac_addresses[2],flow->dup_mac_addresses[3]);
    }*/
	float traffic_duration;
	long long unsigned int flowstarttime;
	long long unsigned int flowendtime;
	long long unsigned int normal_flowstarttime;
	long long unsigned int normal_flowendtime;


    traffic_duration = (flow->end_time.tv_sec*1000000 + flow->end_time.tv_usec) - (flow->start_time.tv_sec*1000000 + flow->start_time.tv_usec);
    traffic_duration = traffic_duration/1000000;
    if(traffic_duration !=0 )
      {
      	float bit_rate = ((flow->bytes*8)/traffic_duration) ;
      	float packets_rate = (flow->packets/traffic_duration);
     // 	printf(" Packets/Sec:%.3f  Bits/Sec:%.3f Duration(sec):%.3f", packets_rate, bit_rate, traffic_duration);
      }

   // printf("\n");
#endif
  } else {
#ifdef HAVE_JSON_C
    jObj = json_object_new_object();

    json_object_object_add(jObj,"protocol",json_object_new_string(ipProto2Name(flow->protocol)));
    json_object_object_add(jObj,"host_a.name",json_object_new_string(flow->lower_name));
    json_object_object_add(jObj,"host_a.port",json_object_new_int(ntohs(flow->lower_port)));
    json_object_object_add(jObj,"host_b.name",json_object_new_string(flow->upper_name));
    json_object_object_add(jObj,"host_n.port",json_object_new_int(ntohs(flow->upper_port)));
    json_object_object_add(jObj,"detected.protocol",json_object_new_int(flow->detected_protocol));
    json_object_object_add(jObj,"detected.protocol.name",json_object_new_string(ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol)));
    json_object_object_add(jObj,"packets",json_object_new_int(flow->packets));
    json_object_object_add(jObj,"bytes",json_object_new_int(flow->bytes));

    if(flow->host_server_name[0] != '\0')
      json_object_object_add(jObj,"host.server.name",json_object_new_string(flow->host_server_name));

    if((flow->ssl.client_certificate[0] != '\0') || (flow->ssl.server_certificate[0] != '\0')) {
      json_object *sjObj = json_object_new_object();

      if(flow->ssl.client_certificate[0] != '\0')
        json_object_object_add(sjObj, "client", json_object_new_string(flow->ssl.client_certificate));

      if(flow->ssl.server_certificate[0] != '\0')
        json_object_object_add(sjObj, "server", json_object_new_string(flow->ssl.server_certificate));

      json_object_object_add(jObj, "ssl", sjObj);
    }

    //flow->protos.ssl.client_certificate, flow->protos.ssl.server_certificate);
    if(json_flag == 1)
      json_object_array_add(jArray_known_flows,jObj);
    else if(json_flag == 2)
      json_object_array_add(jArray_unknown_flows,jObj);
#endif
  }
}

/* ***************************************************** */

static void free_ndpi_flow(struct ndpi_flow *flow) {
  if(flow->ndpi_flow) { ndpi_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       }
}

/* ***************************************************** */

static void ndpi_flow_freer(void *node) {
  struct ndpi_flow *flow = (struct ndpi_flow*)node;

if(flow->flow_file)
  {
	pcap_close(flow->pd);
	pcap_dump_close(flow->flow_file);
	flow ->flow_file = NULL;
  }
  free_ndpi_flow(flow);
  ndpi_free(flow);
}

/* ***************************************************** */

static void node_count_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;
  u_int16_t num = *((u_int16_t*)user_data);

  if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
    *((u_int16_t*)user_data) = num + 1;
}

/* ***************************************************** */

static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if(flow->detected_protocol != 0 /* UNKNOWN */) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)){ /* Avoid walking the same node multiple times */
    if(verbose < 3) {
      printFlow(thread_id, flow);
    }
  }
}
/* ***************************************************** */

static void node_print_known_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if(flow->detected_protocol == 0 /* UNKNOWN */) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)){ /* Avoid walking the same node multiple times */
    finalFlowResults(thread_id, flow);
    if(verbose < 3) printFlow(thread_id, flow);
  }
}


/* ***************************************************** */

static unsigned int node_guess_undetected_protocol(u_int16_t thread_id,
                                                   struct ndpi_flow *flow) {
  flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_thread_info[thread_id].ndpi_struct,
                                                           flow->protocol,
                                                           ntohl(flow->lower_ip),
                                                           ntohs(flow->lower_port),
                                                           ntohl(flow->upper_ip),
                                                           ntohs(flow->upper_port));
  // printf("Guess state: %u\n", flow->detected_protocol);
  if(flow->detected_protocol != 0)
    ndpi_thread_info[thread_id].stats.guessed_flow_protocols++;

  return flow->detected_protocol;
}

/* ***************************************************** */

static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

#if 0
  printf("<%d>Walk on node %s (%p)\n",
         depth,
         which == preorder?"preorder":
         which == postorder?"postorder":
         which == endorder?"endorder":
         which == leaf?"leaf": "unknown",
         flow);
#endif

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(enable_protocol_guess) {
      if(flow->detected_protocol == 0 /* UNKNOWN */) {
        node_guess_undetected_protocol(thread_id, flow);
        // printFlow(thread_id, flow);
      }
    }

    ndpi_thread_info[thread_id].stats.protocol_counter[flow->detected_protocol]       += flow->packets;
    ndpi_thread_info[thread_id].stats.protocol_counter_bytes[flow->detected_protocol] += flow->bytes;
    ndpi_thread_info[thread_id].stats.protocol_flows[flow->detected_protocol]++;
  }
}

/* ***************************************************** */

static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

  if(ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(flow->last_seen + MAX_IDLE_TIME < ndpi_thread_info[thread_id].last_time) {

      /* update stats */
      node_proto_guess_walker(node, which, depth, user_data);

      if (flow->detected_protocol == 0 /* UNKNOWN */ && !undetected_flows_deleted)
        undetected_flows_deleted = 1;
 
      free_ndpi_flow(flow);
      ndpi_thread_info[thread_id].stats.ndpi_flow_count--;

      /* adding to a queue (we can't delete it from the tree inline ) */
      ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
    }
  }
}

/* ***************************************************** */

static int node_cmp(const void *a, const void *b) {
  struct ndpi_flow *fa = (struct ndpi_flow*)a;
  struct ndpi_flow *fb = (struct ndpi_flow*)b;

  //if(fa->vlan_id   < fb->vlan_id  )   return(-1); else { if(fa->vlan_id   > fb->vlan_id  )   return(1); }
  if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  return(0);
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow(u_int16_t thread_id,
				       const u_int8_t version,
				       u_int16_t vlan_id,
				       const struct ndpi_iphdr *iph,
				       u_int16_t ip_offset,
				       u_int16_t ipsize,
				       u_int16_t l4_packet_len,
				       struct ndpi_id_struct **src,
				       struct ndpi_id_struct **dst,
				       u_int8_t *proto,
				       const struct ndpi_ip6_hdr *iph6) {
  u_int32_t idx, l4_offset;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_sctphdr *sctph = NULL;
  struct ndpi_udphdr *udph = NULL;
  struct ndpi_tcphdr *httph = NULL;
  struct ndpi_udphdr *siph = NULL;
  struct ndpi_tcphdr *sipht = NULL;
  u_int32_t left_side_ip;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int32_t verification_tag;
  u_int32_t checksum;
  u_int8_t chunktype;
  u_int8_t sctp_offset = 0;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t not_single_side;
  u_int8_t get_in_flow;
  u_int8_t post_in_flow;
  u_int8_t head_in_flow;
  u_int16_t frag_off = 0;
  struct ndpi_flow flow;
  u_int32_t sip_invite_inflow = 0, sip_200_ok_inflow = 0;
  void *ret;
  u_int8_t *l3;
  
  /*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == 4) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       || (iph->frag_off & htons(0x1FFF)) != 0)
      return NULL;

    l4_offset = iph->ihl * 4;
    l3 = (u_int8_t*)iph;
  } else {
    l4_offset = sizeof(struct ndpi_ip6_hdr);
    l3 = (u_int8_t*)iph6;
  }

  if(l4_packet_len < 64)
    ndpi_thread_info[thread_id].stats.packet_len[0]++;
  else if(l4_packet_len >= 64 && l4_packet_len < 128)
    ndpi_thread_info[thread_id].stats.packet_len[1]++;
  else if(l4_packet_len >= 128 && l4_packet_len < 256)
    ndpi_thread_info[thread_id].stats.packet_len[2]++;
  else if(l4_packet_len >= 256 && l4_packet_len < 1024)
    ndpi_thread_info[thread_id].stats.packet_len[3]++;
  else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
    ndpi_thread_info[thread_id].stats.packet_len[4]++;
  else if(l4_packet_len >= 1500)
    ndpi_thread_info[thread_id].stats.packet_len[5]++;

  if(l4_packet_len > ndpi_thread_info[thread_id].stats.max_packet_len)
    ndpi_thread_info[thread_id].stats.max_packet_len = l4_packet_len;

  if(iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  *proto = iph->protocol;
  frag_off = ntohs(iph->frag_off);
  if(iph->protocol == 6 && l4_packet_len >= 20) 
  {
    ndpi_thread_info[thread_id].stats.tcp_count++;
           
    // tcp
    tcph = (struct ndpi_tcphdr *) ((u_int8_t *) l3 + l4_offset);
    int tcp_header_len = 4 * (int)tcph->doff;
    httph = (struct ndpi_tcphdr *) ((u_int8_t *) l3 + l4_offset + tcp_header_len);
    char *http_r_methode =(char *) malloc(10*sizeof(char));

    if(iph->saddr < iph->daddr) {
      lower_port = tcph->source;
      upper_port = tcph->dest;
    } else {
      lower_port = tcph->dest;
      upper_port = tcph->source;
      if(iph->saddr == iph->daddr) {
        if(lower_port > upper_port) {
          u_int16_t p = lower_port;

          lower_port = upper_port;
          upper_port = p;
        }
      }
    }
    if( tcp_header_len >= 20 && tcp_header_len <= 60 && ipsize > (tcp_header_len + l4_offset) ){
      memcpy(http_r_methode, httph,sizeof(httph));
      if(memcmp(http_r_methode, "GET ", 4) == 0){      
	  ndpi_thread_info[thread_id].stats.http_get_count++;
          ndpi_thread_info[thread_id].stats.http_avg_get_size+=ipsize;
      	  flow.get_in_flow = 1;
          //printf("http request is : %s %u %X %X\n", http_r_methode, ntohl(tcph->ack_seq), tcph->dest, ntohl(tcph->source/*, sizeof(httph)*/)); 
      }
      else if(memcmp(http_r_methode, "POST", 4) == 0){      
	  ndpi_thread_info[thread_id].stats.http_post_count++;
          ndpi_thread_info[thread_id].stats.http_avg_post_size+=l4_packet_len;
          flow.post_in_flow = 1;
      	  //printf("http request is : %s %u %X %X\n", http_r_methode, ntohl(tcph->ack_seq), tcph->dest, ntohl(tcph->source)); 
      }
      else if(memcmp(http_r_methode, "HEAD", 4) == 0){      
	  ndpi_thread_info[thread_id].stats.http_head_count++;
          ndpi_thread_info[thread_id].stats.http_avg_head_size+=l4_packet_len;
          flow.head_in_flow = 1;
      	  //printf("http request is : %s %u %X %X\n", http_r_methode, ntohl(tcph->ack_seq), tcph->dest, ntohl(tcph->source)); 
      }
     free(http_r_methode);

    }

    // look for SIP req methodes
    //if( ntohs(lower_port) == 5060 || ntohs(upper_port) == 5060 ){
      sipht = (struct ndpi_tcphdr *) ((u_int8_t *) l3 + l4_offset + tcp_header_len);
      char *sipt_r_methode =(char *) malloc(20*sizeof(char));
      char *sipt_isup =(char *) malloc(10*sizeof(char));
      char *sipt_content_type =(char *) malloc(60);
      char *sipt_rtpmap =(char *) malloc(40*sizeof(char));
      int i;
      memcpy(sipt_r_methode, sipht,3*sizeof(sipht));
      if(memcmp(sipt_r_methode, "SIP/2.0 200 OK", 12) == 0){      
	  fprintf(f_per_sip_peer,",200_OK,%d.%d.%d.%d,%d.%d.%d.%d \n",
		(ntohl(lower_ip) & 0xFF000000) >> 24,
		(ntohl(lower_ip) & 0x00FF0000) >> 16,
		(ntohl(lower_ip) & 0x0000FF00) >> 8,
		(ntohl(lower_ip) & 0x000000FF), 
		(ntohl(upper_ip) & 0xFF000000) >> 24, 
		(ntohl(upper_ip) & 0x00FF0000) >> 16, 
		(ntohl(upper_ip) & 0x0000FF00) >> 8, 
		(ntohl(upper_ip) & 0x000000FF));
                
		for(i=50; i < (l4_packet_len - 10) ; i++) {
                  sipht = (struct ndpi_tcphdr *) ((u_int8_t *) l3 + l4_offset + tcp_header_len + i);
                  memcpy(sipt_rtpmap, sipht, 40);
                  memcpy(sipt_content_type, sipht, 55);
                  if(memcmp(sipt_rtpmap, "rtpmap:", 7) == 0) {
		      fprintf(f_sip_codecs, ",200_OK,%s \n", sipt_rtpmap);
                  }
                  if(memcmp(sipt_rtpmap, "tcptl t38", 9) == 0) {
	              fprintf(f_sip_codecs, ",200_OK,TCPTL:T38 \n");
	          }
                  if(memcmp(sipt_content_type, "Content-Type: application", 25) == 0) {
		      fprintf(f_sip_content_type,",200_OK,%s \n", sipt_content_type);
                  }
              }
      }else if(memcmp(sipt_r_methode, "INVITE", 6) == 0){      
	  fprintf(f_per_sip_peer,",INVITE,%d.%d.%d.%d,%d.%d.%d.%d \n",
		(ntohl(lower_ip) & 0xFF000000) >> 24,
		(ntohl(lower_ip) & 0x00FF0000) >> 16,
		(ntohl(lower_ip) & 0x0000FF00) >> 8,
		(ntohl(lower_ip) & 0x000000FF), 
		(ntohl(upper_ip) & 0xFF000000) >> 24, 
		(ntohl(upper_ip) & 0x00FF0000) >> 16, 
		(ntohl(upper_ip) & 0x0000FF00) >> 8, 
		(ntohl(upper_ip) & 0x000000FF));
	  ndpi_thread_info[thread_id].stats.sip_invite_count++;
          for(i=50; i < (l4_packet_len - 10); i++) {
              sipht = (struct ndpi_tcphdr *) ((u_int8_t *) l3 + l4_offset + tcp_header_len + i);
              memcpy(sipt_isup, sipht, 3*sizeof(sipht));
              memcpy(sipt_content_type, sipht, 55);
              memcpy(sipt_rtpmap, sipht, 40);
              if(memcmp(sipt_content_type, "Content-Type: application", 25) == 0) {
                fprintf(f_sip_content_type, ",INVITE,%s \n", sipt_content_type);
              }
              if(memcmp(sipt_rtpmap, "tcptl t38", 9) == 0) {
	        fprintf(f_sip_codecs, ",INVITE,TCPTL:T38 \n");
	      }
              if(memcmp(sipt_rtpmap, "rtpmap:", 7) == 0) {
	        fprintf(f_sip_codecs, ",INVITE,%s \n", sipt_rtpmap);
              }
          }
      }else if(memcmp(sipt_r_methode, "CANCEL", 6) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_cancel_count++;
      }else if(memcmp(sipt_r_methode, "PRACK", 5) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_prack_count++;
      }else if(memcmp(sipt_r_methode, "BYE", 3) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_bye_count++;
      }else if(memcmp(sipt_r_methode, "OPTIONS", 7) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_options_count++;
      }else if(memcmp(sipt_r_methode, "ACK", 3) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_ack_count++;
      }

      free(sipt_r_methode);
      //  }
 
  } else if(iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    ndpi_thread_info[thread_id].stats.udp_count++;
    udph = (struct ndpi_udphdr *) ((u_int8_t *) l3 + l4_offset);
    int udp_header_len = 8;
    if(iph->saddr < iph->daddr) {
      lower_port = udph->source;
      upper_port = udph->dest;
    } else {
      lower_port = udph->dest;
      upper_port = udph->source;
    }
    // look for h248 over udp
    //if( ntohs(lower_port) == 2944 || ntohs(upper_port) == 2944 )
    //	ndpi_thread_info[thread_id].stats.h248_count++;

    // look for SIP req methodes
    //if( ntohs(lower_port) == 5060 || ntohs(upper_port) == 5060 ){
    if(1==1){
      siph = (struct ndpi_udphdr *) ((u_int8_t *) l3 + l4_offset + udp_header_len);
      char *sip_r_methode =(char *) malloc(20*sizeof(char));
      char *sip_isup =(char *) malloc(10*sizeof(char));
      char *sip_content_type =(char *) malloc(60);
      char *sip_rtpmap =(char *) malloc(40*sizeof(char));
      int i;
      memcpy(sip_r_methode, siph,3*sizeof(siph));
      if(memcmp(sip_r_methode, "SIP/2.0 200 OK", 12) == 0){      
	  fprintf(f_per_sip_peer,",200_OK,%d.%d.%d.%d,%d.%d.%d.%d \n",
		(ntohl(lower_ip) & 0xFF000000) >> 24,
		(ntohl(lower_ip) & 0x00FF0000) >> 16,
		(ntohl(lower_ip) & 0x0000FF00) >> 8,
		(ntohl(lower_ip) & 0x000000FF), 
		(ntohl(upper_ip) & 0xFF000000) >> 24, 
		(ntohl(upper_ip) & 0x00FF0000) >> 16, 
		(ntohl(upper_ip) & 0x0000FF00) >> 8, 
		(ntohl(upper_ip) & 0x000000FF));
              for(i=50; i < (l4_packet_len - 10); i++) {
                  siph = (struct ndpi_udphdr *) ((u_int8_t *) l3 + l4_offset + udp_header_len + i);
                  memcpy(sip_rtpmap, siph, 40);
                  memcpy(sip_content_type, siph, 55);
                  if(memcmp(sip_rtpmap, "rtpmap:", 7) == 0) {
		      fprintf(f_sip_codecs, ",200_OK,%s \n", sip_rtpmap);
		      //memset(&siph, 0, 400*sizeof(char));
                  }
              	  if(memcmp(sip_rtpmap, "udptl t38", 9) == 0) {
	              fprintf(f_sip_codecs, ",200_OK,UDPTL:T38 \n");
	          }
                  if(memcmp(sip_content_type, "Content-Type: application", 25) == 0) {
		      fprintf(f_sip_content_type,",200_OK,%s \n", sip_content_type);
                  }
      		  siph = NULL;
                 
              }
//	  return;
      }else if(memcmp(sip_r_methode, "INVITE", 6) == 0){      
	  fprintf(f_per_sip_peer,",INVITE,%d.%d.%d.%d,%d.%d.%d.%d \n",
		(ntohl(lower_ip) & 0xFF000000) >> 24,
		(ntohl(lower_ip) & 0x00FF0000) >> 16,
		(ntohl(lower_ip) & 0x0000FF00) >> 8,
		(ntohl(lower_ip) & 0x000000FF), 
		(ntohl(upper_ip) & 0xFF000000) >> 24, 
		(ntohl(upper_ip) & 0x00FF0000) >> 16, 
		(ntohl(upper_ip) & 0x0000FF00) >> 8, 
		(ntohl(upper_ip) & 0x000000FF));
	  //printf("total invites in flow: ");
	  ndpi_thread_info[thread_id].stats.sip_invite_count++;
              for(i=50; i <(l4_packet_len - 10); i++) {
                  siph = (struct ndpi_udphdr *) ((u_int8_t *) l3 + l4_offset + udp_header_len + i);
                  memcpy(sip_isup, siph, 3*sizeof(siph));
                  memcpy(sip_content_type, siph, 55);
                  memcpy(sip_rtpmap, siph, 40);
                  if(memcmp(sip_content_type, "Content-Type: application", 25) == 0) {
		      fprintf(f_sip_content_type, ",INVITE,%s \n", sip_content_type);
                  }
              	  if(memcmp(sip_rtpmap, "udptl t38", 9) == 0) {
		      fprintf(f_sip_codecs, ",INVITE,UDPTL:T38 \n");
		  }
                  if(memcmp(sip_rtpmap, "rtpmap:", 7) == 0) {
		      fprintf(f_sip_codecs, ",INVITE,%s \n", sip_rtpmap);
		      //memset(&siph, 0, 400*sizeof(char));
      		  siph = NULL;
                  }
              }
	//memset(&siph, 0, 400*sizeof(siph));
      }else if(memcmp(sip_r_methode, "CANCEL", 6) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_cancel_count++;
      }else if(memcmp(sip_r_methode, "PRACK", 5) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_prack_count++;
      }else if(memcmp(sip_r_methode, "BYE", 3) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_bye_count++;
      }else if(memcmp(sip_r_methode, "OPTIONS", 7) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_options_count++;
      }else if(memcmp(sip_r_methode, "ACK", 3) == 0){      
	  ndpi_thread_info[thread_id].stats.sip_ack_count++;
      }
      free(sip_r_methode);

    }
   
  } else if(iph->protocol == 132 && l4_packet_len >= 12) {
    // sctp
    sctph = (struct ndpi_sctphdr *) ((u_int8_t *) l3 + l4_offset + sctp_offset );

    if(iph->saddr < iph->daddr) {
      lower_port = sctph->source;
      upper_port = sctph->dest;
    } else {
      lower_port = sctph->dest;
      upper_port = sctph->source;
      if(iph->saddr == iph->daddr) {
        if(lower_port > upper_port) {
          u_int16_t p = lower_port;

          lower_port = upper_port;
          upper_port = p;
        }
      }
    }
    //printf ("the sctp ports are: %d <=> %d \n", ntohs(lower_port), ntohs(upper_port));
    //printf ("the first sctp chunktype is: %x \n", sctph->chunktype);
    while ( sctph->chunktype != 0 ) {
	//printf ("the sctp verification tag is: %x \n", ntohl(sctph->verification_tag));
	//printf ("the sctp checksum is: %x \n", ntohl(sctph->checksum));
	sctp_offset += 16;
    	sctph = (struct ndpi_sctphdr *) ((u_int8_t *) l3 + l4_offset + sctp_offset );
	//printf ("the second sctp chunktype is:******* %x \n", sctph->chunktype);
    	//printf ("chunk len is ******* %d\n", ntohs(sctph->chunklen));
    //	printf ("chunk stream id is ********* %d\n", ntohs(sctph->chunksid));
    } 
    //printf ("ip total len is : %d\n", ntohs(iph->tot_len));
    if ( ntohl(sctph->ppid) == 3 && ntohs(iph->tot_len) >= 64 ){
	
    //	printf ("mtp3 is detected %d\n", ntohl(sctph->ppid));
    //	printf ("mtp3 SI id is ******* %d\n", sctph->mtp3sid);
    	if ( sctph->mtp3sid == 14 ){
    		ndpi_thread_info[thread_id].stats.h248_count++;
    	//	printf ("chunk len is ******* %d\n", ntohs(sctph->chunklen));
    	//	printf ("mtp3 SI id is ******* %d\n", sctph->mtp3sid);
	}else if ( sctph->mtp3sid == 3 ){
    		ndpi_thread_info[thread_id].stats.sccp_count++;
    	//	printf ("chunk len is ******* %d\n", ntohs(sctph->chunklen));
    	//	printf ("mtp3 SI id is ******* %d\n", sctph->mtp3sid);
	}else if ( sctph->mtp3sid == 5 ){
    		ndpi_thread_info[thread_id].stats.isup_count++;
    	//	printf ("chunk len is ******* %d\n", ntohs(sctph->chunklen));
    	//	printf ("mtp3 SI id is ******* %d\n", sctph->mtp3sid);
	}else if ( sctph->mtp3sid == 13 ){
    		ndpi_thread_info[thread_id].stats.bicc_count++;
    	//	printf ("chunk len is ******* %d\n", ntohs(sctph->chunklen));
    	//	printf ("mtp3 SI id is ******* %d\n", sctph->mtp3sid);
	}
    } else if ( ntohl(sctph->ppid) == 7 ) {
	ndpi_thread_info[thread_id].stats.h248_count++;
      }       	
   // printf ("chunk len is %d\n", ntohs(sctph->chunklen));
   // printf ("chunk stream id is %d\n", ntohs(sctph->chunksid));
    
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
  /*flow.left_side_ip = iph->saddr ,*/ flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
  flow.lower_port = lower_port, flow.upper_port = upper_port;

  if(0)
    printf("[NDPI] [%u][%u:%hu <-> %u:%u]\n",
           iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

  idx = (/*vlan_id +*/ lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
  ret = ndpi_tfind(&flow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp);
  
  if(ret == NULL) 
  {
    if(ndpi_thread_info[thread_id].stats.ndpi_flow_count == MAX_NDPI_FLOWS) {
      printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
      exit(-1);
    } 
    else 
    {
      struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

      if(newflow == NULL) {
        printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
        return(NULL);
      }

      memset(newflow, 0, sizeof(struct ndpi_flow));
      newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;
      newflow->left_side_ip = iph->saddr;

      if(version == 4) 
      {
        inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
        inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
        newflow->syn_ip_id = iph->id;
      } else {
        inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
        inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
        newflow->syn_ip_id = 0;      //No packet id in ipv6
      }

      if((newflow->ndpi_flow = malloc_wrapper(size_flow_struct)) == NULL) {
        printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
        return(NULL);
      } else
        memset(newflow->ndpi_flow, 0, size_flow_struct);

      if((newflow->src_id = malloc_wrapper(size_id_struct)) == NULL) {
        printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
        return(NULL);
      } else
        memset(newflow->src_id, 0, size_id_struct);

      if((newflow->dst_id = malloc_wrapper(size_id_struct)) == NULL) {
        printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
        return(NULL);
      } else
        memset(newflow->dst_id, 0, size_id_struct);

      ndpi_tsearch(newflow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp); /* Add */
      ndpi_thread_info[thread_id].stats.ndpi_flow_count++;
/*      if(tot_usec = 1000000) {
        printf("\tUnique flows:                     %-13u\n", ndpi_thread_info[thread_id].stats.ndpi_flow_count);
      }
*/

      *src = newflow->src_id, *dst = newflow->dst_id;

      // printFlow(thread_id, newflow);
      newflow->is_dup = 0;
      
      return(newflow);
    }
  } 
  else 
  {
    struct ndpi_flow *flow = *(struct ndpi_flow**)ret;

    if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;
    
    return flow;
  }
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow6(u_int16_t thread_id,
					u_int16_t vlan_id,
					const struct ndpi_ip6_hdr *iph6,
					u_int16_t ip_offset,
					struct ndpi_id_struct **src,
					struct ndpi_id_struct **dst,
					u_int8_t *proto) {
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = 4;
  iph.saddr = iph6->ip6_src.__u6_addr.__u6_addr32[2] + iph6->ip6_src.__u6_addr.__u6_addr32[3];
  iph.daddr = iph6->ip6_dst.__u6_addr.__u6_addr32[2] + iph6->ip6_dst.__u6_addr.__u6_addr32[3];
  iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  return(get_ndpi_flow(thread_id, 6, vlan_id, &iph, ip_offset,
		       sizeof(struct ndpi_ip6_hdr),
		       ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
		       src, dst, proto, iph6));
 
}

/* ***************************************************** */

static void setupDetection(u_int16_t thread_id) {
  NDPI_PROTOCOL_BITMASK all;

  memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));

  // init global detection structure
  ndpi_thread_info[thread_id].ndpi_struct = ndpi_init_detection_module(detection_tick_resolution, malloc_wrapper, free_wrapper, debug_printf);
  if(ndpi_thread_info[thread_id].ndpi_struct == NULL) {
    printf("ERROR: global structure initialization failed\n");
    exit(-1);
  }

  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].ndpi_struct, &all);

  // allocate memory for id and flow tracking
  size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
  size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

  // clear memory for results
  memset(ndpi_thread_info[thread_id].stats.protocol_counter, 0, sizeof(ndpi_thread_info[thread_id].stats.protocol_counter));
  memset(ndpi_thread_info[thread_id].stats.protocol_counter_bytes, 0, sizeof(ndpi_thread_info[thread_id].stats.protocol_counter_bytes));
  memset(ndpi_thread_info[thread_id].stats.protocol_flows, 0, sizeof(ndpi_thread_info[thread_id].stats.protocol_flows));
  
  
  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_thread_info[thread_id].ndpi_struct, _protoFilePath);
}

/* ***************************************************** */

static void terminateDetection(u_int16_t thread_id) {
  int i;

  for(i=0; i<NUM_ROOTS; i++) {
    ndpi_tdestroy(ndpi_thread_info[thread_id].ndpi_flows_root[i], ndpi_flow_freer);
    ndpi_thread_info[thread_id].ndpi_flows_root[i] = NULL;
  }

  ndpi_exit_detection_module(ndpi_thread_info[thread_id].ndpi_struct, free_wrapper);
}

/* ***************************************************** */


// ipsize = header->len - ip_offset ; rawsize = header->len
static unsigned int packet_processing(u_int16_t thread_id,
				      const u_int64_t time,
				      u_int16_t vlan_id,
				      const struct ndpi_iphdr *iph,
				      struct ndpi_ip6_hdr *iph6,
				      u_int16_t ip_offset,
				      u_int16_t ipsize, u_int16_t rawsize,
                                      const struct timeval *packet_time,
                                      pcap_dumper_t **dumper,
                                      const u_char* source_mac, const u_char* dest_mac) {
  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow *flow;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int32_t i, protocol = 0;
  u_int8_t proto;

  last_flowendtime = packet_time->tv_sec*1000000 + packet_time->tv_usec;
  last_flowendtime_sec = packet_time->tv_sec;
  
  if(iph)
  {
    flow = get_ndpi_flow(thread_id, 4, vlan_id, iph, ip_offset, ipsize,
			 ntohs(iph->tot_len) - (iph->ihl * 4),
			 &src, &dst, &proto, NULL);
 
    //printFlow(thread_id,flow);
  }
  
  else
    flow = get_ndpi_flow6(thread_id, vlan_id, iph6, ip_offset, &src, &dst, &proto);

  if(flow != NULL) 
  { //Not a new flow 

    ndpi_thread_info[thread_id].stats.ip_packet_count++;
    ndpi_thread_info[thread_id].stats.total_wire_bytes += rawsize + 24 /* CRC etc */, ndpi_thread_info[thread_id].stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;
   // flow->packets++, flow->bytes += rawsize;
    flow->last_seen = time;
    
    
    if(ndpi_flow && ndpi_flow->packet.tcp && flow->syn_ip_id != 0  && ndpi_flow->packet.tcp->syn != 0
           && ndpi_flow->packet.tcp->ack == 0
           && ndpi_flow->init_finished != 0 && iph->id == flow->syn_ip_id)
    {
        flow->is_dup = 1;
        ndpi_thread_info[thread_id].stats.dup_flows++;
        memcpy(flow->dup_mac_addresses[2], source_mac, 6 );
        memcpy(flow->dup_mac_addresses[3], dest_mac, 6 );        
    }
    if(flow->packets == 0)
    {   //new flow
        flow->start_time.tv_sec = packet_time->tv_sec;
	//printf("flow_start_time : %d\n", flow->start_time.tv_sec);
        flow->start_time.tv_usec = packet_time->tv_usec;
        memcpy(flow->dup_mac_addresses[0], source_mac, 6 );
        memcpy(flow->dup_mac_addresses[1], dest_mac, 6 );


	/*if(ndpi_flow->packet.tcp_retransmission == 0){
		printf("TCP retransmission\n");
	}*/


	long long unsigned int flowstarttime;
	long long unsigned int flowendtime;
	long long unsigned int normal_flowstarttime;
	long long unsigned int normal_flowendtime;





   /*Connections Statistics per flow*/
        long long unsigned int ARR_flowstarttime;
        long long unsigned int ARR_flowendtime;
        long long unsigned int ARR_normal_flowstarttime;
    	ARR_flowstarttime = flow->start_time.tv_sec;
    	ARR_normal_flowstarttime = ARR_flowstarttime - analysis_start_time;
	NEW_CONNECTIONS_ARR[ARR_normal_flowstarttime]++;

	if(flow->protocol == IPPROTO_TCP) {
  		if(ntohs(flow->upper_port) == 80 || ntohs(flow->lower_port) == 80)
  		{     //I will count all port 80 as HTTP traffic
  		    total_http_flows++;
		    HTTP_CONNECTIONS_ARR[ARR_normal_flowstarttime]++;	
	    	
	  	}
	  	if(ntohs(flow->upper_port) == 443 || ntohs(flow->lower_port) == 443)
	  	{     //I will count all port 443 as SSL traffic
	  	    total_ssl_flows++;
		    SSL_CONNECTIONS_ARR[ARR_normal_flowstarttime]++;	
  		}
	    	total_tcp_flows++;
	    	TCP_CONNECTIONS_ARR[ARR_normal_flowstarttime]++;
	}

	if(flow->protocol == IPPROTO_UDP) {
	    total_udp_flows++;
	    UDP_CONNECTIONS_ARR[ARR_normal_flowstarttime]++;
	}

    }
    if(flow->flow_file == NULL && output_dir != NULL && flow->is_dup)
    {
        pcap_t *pd;
          pcap_dumper_t *pdumper;
          char file_name[256];
          snprintf(file_name, sizeof(file_name), "%s%s_%u_%s_%u_%s_%u.pcap", output_dir, ipProto2Name(flow->protocol),
                          flow->vlan_id, flow->lower_name, ntohs(flow->lower_port),
                                         flow->upper_name, ntohs(flow->upper_port));


          pd = pcap_open_dead(DLT_EN10MB, 65535);
          // Create the output file. 

          pdumper = pcap_dump_open(pd, file_name);

          if(pdumper == NULL)
          {
              printf("%s",pcap_geterr(pd));
              fprintf(stderr, "Unable to create flow file %s\n", file_name);
          }

          flow->flow_file = pdumper;
          flow->pd = pd;
           
        
    }
    
  if(output_dir !=  NULL && packets_per_file > 0 && flow ->flow_file != NULL)
    {
    	if(flow->packets >= packets_per_file)
    	{
            //Close flow output file
            pcap_close(flow->pd);
            pcap_dump_close(flow->flow_file);
            flow ->flow_file = NULL;
    	}
    }
    *dumper = flow->flow_file;

    flow->end_time.tv_sec = packet_time->tv_sec;
    flow->end_time.tv_usec = packet_time->tv_usec;

    flow->packets++, flow->bytes += rawsize;

    flow->last_seen = time;
    if(flow->packets > 1 && flow->not_single_side == 0 && iph)
    {    
        if(flow->left_side_ip == iph->daddr)
        {
         flow->not_single_side++;
         single_side_flow_count++;
        }
    }
    if(flow->get_in_flow == 1)
        flows_with_get++;
    if(flow->post_in_flow == 1)
        flows_with_post++;
    if(flow->head_in_flow == 1)
        flows_with_head++;

        
    
  }
  else 
  {
    return(0);
  }
  if(flow->detection_completed) return(0);

  protocol = (const u_int32_t)ndpi_detection_process_packet(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow,
                                                            iph ? (uint8_t *)iph : (uint8_t *)iph6,
                                                            ipsize, time, src, dst);

  flow->detected_protocol = protocol;
  

 
  if(flow->is_dup && flow->detected_protocol == NDPI_PROTOCOL_HTTP )
  { //duplicated HTTP
      ndpi_thread_info[thread_id].stats.dup_http_flows++;
  }
  if(flow->is_dup && flow->detected_protocol == NDPI_PROTOCOL_SSL )
  { //duplicated SSL
      ndpi_thread_info[thread_id].stats.dup_ssl_flows++;
  }
  if(flow->is_dup && flow->detected_protocol > 0 && flow->detected_protocol != NDPI_PROTOCOL_HTTP)
  {   
      if(ntohs(flow->upper_port) == 80 || ntohs(flow->lower_port) == 80)
      {     //I will count all port 80 as HTTP traffic
          ndpi_thread_info[thread_id].stats.dup_http_flows++;
      }
      if(ntohs(flow->upper_port) == 443 || ntohs(flow->lower_port) == 443)
      {     //I will count all port 443 as SSL traffic
          ndpi_thread_info[thread_id].stats.dup_http_flows++;
      }
  }
 
  
  if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
     || ((proto == IPPROTO_UDP) && (flow->packets > 8))
     || ((proto == IPPROTO_TCP) && (flow->packets > 10))) 
  {
    flow->detection_completed = 1;
    
    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);

    if((proto == IPPROTO_TCP) && (flow->detected_protocol != NDPI_PROTOCOL_DNS)) {
      snprintf(flow->ssl.client_certificate, sizeof(flow->ssl.client_certificate), "%s", flow->ndpi_flow->protos.ssl.client_certificate);
      snprintf(flow->ssl.server_certificate, sizeof(flow->ssl.server_certificate), "%s", flow->ndpi_flow->protos.ssl.server_certificate);
    }
   
#if 0
    {
      struct ndpi_int_one_line_struct ret;
      ndpi_http_method m;
      ndpi_get_http_url(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow, &ret);     
      ndpi_get_http_content_type(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow, &ret);    
      m = ndpi_get_http_method(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow);
      
    }
#endif

    free_ndpi_flow(flow);





    if(verbose > 1) {
      if(enable_protocol_guess) {
        if(flow->detected_protocol == 0 /* UNKNOWN */) {
          protocol = node_guess_undetected_protocol(thread_id, flow);
        }
      }

      //printFlow(thread_id, flow);
      //finalFlowResults(thread_id, flow);
    }

  }

#if 0
  if(ndpi_flow->l4.tcp.host_server_name[0] != '\0')
    printf("%s\n", ndpi_flow->l4.tcp.host_server_name);
#endif

  if(live_capture) {
    if(ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].last_time) {
      /* scan for idle flows */
      ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_idle_scan_walker, &thread_id);

      /* remove idle flows (unfortunately we cannot do this inline) */
      while (ndpi_thread_info[thread_id].num_idle_flows > 0)
        ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
                     &ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_cmp);

      if(++ndpi_thread_info[thread_id].idle_scan_idx == NUM_ROOTS) ndpi_thread_info[thread_id].idle_scan_idx = 0;
      ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].last_time;
    }
  }
  return 0;
}



/* ****************************************************** */

char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < 1048576) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
        snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
        snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

/* ***************************************************** */

char* formatPackets(float numPkts, char *buf) {
  if(numPkts < 1000) {
    snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}

/* ***************************************************** */

#ifdef HAVE_JSON_C
static void json_init() {
  jArray_known_flows = json_object_new_array();
  jArray_unknown_flows = json_object_new_array();
}
#endif

/* ***************************************************** */

char* formatBytes(u_int32_t howMuch, char *buf, u_int buf_len) {
  char unit = 'B';

  if(howMuch < 1024) {
    snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
  } else if(howMuch < 1048576) {
    snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
  } else {
    float tmpGB = ((float)howMuch)/1048576;

    if(tmpGB < 1024) {
      snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
    } else {
      tmpGB /= 1024;

      snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
    }
  }

  return(buf);
}

/* ***************************************************** */

static void printResults(u_int64_t tot_usec) {
  u_int32_t i;
  u_int64_t total_flow_bytes = 0;
  u_int avg_pkt_size = 0;
  struct thread_stats cumulative_stats;
  int thread_id;
  double total_vlan = 0;
   
#ifdef HAVE_JSON_C
  FILE *json_fp;
  json_object *jObj_main, *jObj_trafficStats, *jArray_detProto, *jObj;
#endif
  long long unsigned int breed_stats[NUM_BREEDS] = { 0 };

  memset(&cumulative_stats, 0, sizeof(cumulative_stats));

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if(ndpi_thread_info[thread_id].stats.total_wire_bytes == 0) continue;

    for(i=0; i<NUM_ROOTS; i++)
      ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_proto_guess_walker, &thread_id);

    /* Stats aggregation */
    cumulative_stats.guessed_flow_protocols += ndpi_thread_info[thread_id].stats.guessed_flow_protocols;
    cumulative_stats.raw_packet_count += ndpi_thread_info[thread_id].stats.raw_packet_count;
    cumulative_stats.ip_packet_count += ndpi_thread_info[thread_id].stats.ip_packet_count;
    cumulative_stats.total_wire_bytes += ndpi_thread_info[thread_id].stats.total_wire_bytes;
//    tot_eth_gbits_per_sec = ((cumulative_stats.total_wire_bytes * 8));
//    tot_eth_gbits_per_sec = traffic_duration_all;
    cumulative_stats.total_ip_bytes += ndpi_thread_info[thread_id].stats.total_ip_bytes;
    cumulative_stats.total_discarded_bytes += ndpi_thread_info[thread_id].stats.total_discarded_bytes;

    for(i = 0; i < ndpi_get_num_supported_protocols(ndpi_thread_info[0].ndpi_struct); i++) {
      cumulative_stats.protocol_counter[i] += ndpi_thread_info[thread_id].stats.protocol_counter[i];
      cumulative_stats.protocol_counter_bytes[i] += ndpi_thread_info[thread_id].stats.protocol_counter_bytes[i];
      cumulative_stats.protocol_flows[i] += ndpi_thread_info[thread_id].stats.protocol_flows[i];
    }

    cumulative_stats.ndpi_flow_count += ndpi_thread_info[thread_id].stats.ndpi_flow_count;
    
//    if(tot_usec > 10000000000) {
//	printf("\tUnique flows:                     %-13u\n", cumulative_stats.ndpi_flow_count);
//    }
    cumulative_stats.tcp_count   += ndpi_thread_info[thread_id].stats.tcp_count;
    cumulative_stats.http_get_count   += ndpi_thread_info[thread_id].stats.http_get_count;
    cumulative_stats.http_avg_get_size   += ndpi_thread_info[thread_id].stats.http_avg_get_size;
    cumulative_stats.http_post_count   += ndpi_thread_info[thread_id].stats.http_post_count;
    cumulative_stats.http_avg_post_size   += ndpi_thread_info[thread_id].stats.http_avg_post_size;
    cumulative_stats.http_head_count   += ndpi_thread_info[thread_id].stats.http_head_count;
    cumulative_stats.http_avg_head_size   += ndpi_thread_info[thread_id].stats.http_avg_head_size;
    cumulative_stats.tcp_frag    += ndpi_thread_info[thread_id].stats.tcp_frag;
    cumulative_stats.udp_count   += ndpi_thread_info[thread_id].stats.udp_count;
    cumulative_stats.h248_count   += ndpi_thread_info[thread_id].stats.h248_count;
    cumulative_stats.sccp_count   += ndpi_thread_info[thread_id].stats.sccp_count;
    cumulative_stats.isup_count   += ndpi_thread_info[thread_id].stats.isup_count;
    cumulative_stats.bicc_count   += ndpi_thread_info[thread_id].stats.bicc_count;
    cumulative_stats.sip_ack_count   += ndpi_thread_info[thread_id].stats.sip_ack_count;
    cumulative_stats.sip_bye_count   += ndpi_thread_info[thread_id].stats.sip_bye_count;
    cumulative_stats.sip_options_count   += ndpi_thread_info[thread_id].stats.sip_options_count;
    cumulative_stats.sip_invite_count   += ndpi_thread_info[thread_id].stats.sip_invite_count;
    cumulative_stats.sip_cancel_count   += ndpi_thread_info[thread_id].stats.sip_cancel_count;
    cumulative_stats.sip_prack_count   += ndpi_thread_info[thread_id].stats.sip_prack_count;
    cumulative_stats.udp_frag    += ndpi_thread_info[thread_id].stats.udp_frag;
    cumulative_stats.mpls_count  += ndpi_thread_info[thread_id].stats.mpls_count;
    cumulative_stats.pppoe_count += ndpi_thread_info[thread_id].stats.pppoe_count;
    cumulative_stats.vlan_count  += ndpi_thread_info[thread_id].stats.vlan_count;
    cumulative_stats.fragmented_count += ndpi_thread_info[thread_id].stats.fragmented_count;
    
    for(i = 0; i < 4; i++)
    {
        cumulative_stats.vlan_level_count[i] += ndpi_thread_info[thread_id].stats.vlan_level_count[i];
        total_vlan += cumulative_stats.vlan_level_count[i];
    }    
    for(i = 0; i < 4096; i++)
    {
        cumulative_stats.vlan_ids_count[i] += ndpi_thread_info[thread_id].stats.vlan_ids_count[i];
    }
    for(i = 0; i < 6; i++)
      cumulative_stats.packet_len[i] += ndpi_thread_info[thread_id].stats.packet_len[i];
    
    cumulative_stats.max_packet_len += ndpi_thread_info[thread_id].stats.max_packet_len;       
    cumulative_stats.dup_flows += ndpi_thread_info[thread_id].stats.dup_flows;  
    cumulative_stats.dup_http_flows += ndpi_thread_info[thread_id].stats.dup_http_flows;
    cumulative_stats.dup_ssl_flows += ndpi_thread_info[thread_id].stats.dup_ssl_flows;
  }


  if(!json_flag) {







    printf("\nTotal statistics:\n\n");
    if(tot_usec > 0) {
      char buf[32], buf1[32];
      float t = (float)(cumulative_stats.ip_packet_count*1000000)/(last_flowendtime - analysis_start_time_usec);
      float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(last_flowendtime - analysis_start_time_usec);
      float traffic_duration;
      traffic_duration = (last_flowendtime - analysis_start_time_usec);
      traffic_duration_all = traffic_duration;
      traffic_duration_all_sec = (last_flowendtime_sec - analysis_start_time);
      t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)traffic_duration;
      b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)traffic_duration;
      tot_eth_gbits_per_sec = ((cumulative_stats.total_wire_bytes * 8)/traffic_duration_all)/(1024*(1.024*1.024));
      printf("\tTraffic throughput:\t\t  %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
      fprintf(f_general, "Traffic throughput pps,%s\nTraffic throughput per sec,%s\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
      printf("\tTraffic BW Gbps:\t\t  %-13.7f\n", tot_eth_gbits_per_sec);
      fprintf(f_general, "Traffic BW Gbps,%.7f\n", tot_eth_gbits_per_sec);
      printf("\tTraffic duration:\t\t  %.3f sec\n", traffic_duration_all/1000000);
      fprintf(f_general, "Traffic duration sec,%.3f\n\n", traffic_duration_all/1000000);
    }
    printf("\nGeneral statistics:\n\n");
    printf("\t ------------------------------------------------------------------\n");
    printf("\t|Traffic statistics                |Value               |Precentage|\n");
    fprintf(f_general, "Traffic statistics,Value,Precentage\n");
    printf("\t ------------------------------------------------------------------\n");
    printf("\t|Ethernet bytes:                   |%-13llu       |%-10s|\n", (long long unsigned int)cumulative_stats.total_wire_bytes,"100.00 ");
    fprintf(f_general, "Ethernet bytes,%llu,%s\n", (long long unsigned int)cumulative_stats.total_wire_bytes,"100.00 ");
    int ether_type_counter = 0;
    for (ether_type_counter = 0; ether_type_counter < 65535; ether_type_counter++){
          if(ETHER_TYPE_ARR[ether_type_counter] > 0)
                  printf ("\t|Ether_Type 0x%-13x \t   |%-20llu|%6.2f%s|\n",ether_type_counter,ETHER_TYPE_ARR[ether_type_counter],100*(float)ETHER_TYPE_ARR[ether_type_counter]/(float)cumulative_stats.raw_packet_count,"    ");
    //              fprintf (f_general, "Ether_Type 0x%-13x,%-20llu,%6.2f%s\n",ether_type_counter,ETHER_TYPE_ARR[ether_type_counter],100*(float)ETHER_TYPE_ARR[ether_type_counter]/(float)cumulative_stats.raw_packet_count,"    ");
    }
    printf("\t|IP bytes:                         |%-19llu |%6.2f    |\n", (long long unsigned int)cumulative_stats.total_ip_bytes,100*(float)cumulative_stats.total_ip_bytes/(float)cumulative_stats.total_wire_bytes);
    fprintf(f_general, "IP bytes,%llu,%.2f\n", (long long unsigned int)cumulative_stats.total_ip_bytes,100*(float)cumulative_stats.total_ip_bytes/(float)cumulative_stats.total_wire_bytes);
    total_bytes = (float)cumulative_stats.total_ip_bytes;
    printf("\t|Discarded bytes:                  |%-19llu |%6.2f    |\n", (long long unsigned int)cumulative_stats.total_discarded_bytes,100*(float)cumulative_stats.total_discarded_bytes/(float)cumulative_stats.total_wire_bytes);
    fprintf(f_general,"Discarded bytes,%llu,%.2f\n", (long long unsigned int)cumulative_stats.total_discarded_bytes,100*(float)cumulative_stats.total_discarded_bytes/(float)cumulative_stats.total_wire_bytes);
    printf("\t|Total packets:                    |%-13llu       |100.00    |\n", (long long unsigned int)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Total packets,%llu,100.00\n", (long long unsigned int)cumulative_stats.raw_packet_count);
    total_packets = (float)cumulative_stats.raw_packet_count;
    printf("\t|IP packets:                       |%-19llu |%6.2f    |\n", (long long unsigned int)cumulative_stats.ip_packet_count,100*(float)cumulative_stats.ip_packet_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general,"IP packets,%llu,%.2f\n", (long long unsigned int)cumulative_stats.ip_packet_count,100*(float)cumulative_stats.ip_packet_count/(float)cumulative_stats.raw_packet_count);
    
    
    /* In order to prevent Floating point exception in case of no traffic*/
    if(cumulative_stats.total_ip_bytes && cumulative_stats.raw_packet_count)
      avg_pkt_size = (unsigned int)(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count);
    printf("\t|TCP Packets:                      |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.tcp_count,100*(float)cumulative_stats.tcp_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "TCP Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.tcp_count,100*(float)cumulative_stats.tcp_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|IPv6 Packets:                     |%-19llu |%6.2f    |\n", (unsigned long)ipv6_counter,100*(float)ipv6_counter/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "IPv6 Packets,%llu,%.2f\n", (unsigned long)ipv6_counter,100*(float)ipv6_counter/(float)cumulative_stats.raw_packet_count);
    printf("\t|UDP Packets:                      |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.udp_count,100*(float)cumulative_stats.udp_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "UDP Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.udp_count,100*(float)cumulative_stats.udp_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|Total VLAN Packets:               |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.vlan_count,100*(float)cumulative_stats.vlan_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Total VLAN Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.vlan_count,100*(float)cumulative_stats.vlan_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|0 VLAN Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)VLAN_LEVEL_ARR[0],100*(float)VLAN_LEVEL_ARR[0]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "0 VLAN Level Packets,%llu,%.2f\n", (unsigned long)VLAN_LEVEL_ARR[0],100*(float)VLAN_LEVEL_ARR[0]/(float)cumulative_stats.raw_packet_count);
    printf("\t|1 VLAN Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)VLAN_LEVEL_ARR[1],100*(float)VLAN_LEVEL_ARR[1]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "1 VLAN Level Packets,%llu,%.2f\n", (unsigned long)VLAN_LEVEL_ARR[1],100*(float)VLAN_LEVEL_ARR[1]/(float)cumulative_stats.raw_packet_count);
    printf("\t|2 VLAN Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)VLAN_LEVEL_ARR[2],100*(float)VLAN_LEVEL_ARR[2]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "2 VLAN Level Packets,%llu,%.2f\n", (unsigned long)VLAN_LEVEL_ARR[2],100*(float)VLAN_LEVEL_ARR[2]/(float)cumulative_stats.raw_packet_count);
    printf("\t|3 VLAN Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)VLAN_LEVEL_ARR[3],100*(float)VLAN_LEVEL_ARR[3]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "3 VLAN Level Packets,%llu,%.2f\n", (unsigned long)VLAN_LEVEL_ARR[3],100*(float)VLAN_LEVEL_ARR[3]/(float)cumulative_stats.raw_packet_count);
    printf("\t|4 VLAN Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)VLAN_LEVEL_ARR[4],100*(float)VLAN_LEVEL_ARR[4]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "4 VLAN Level Packets,%llu,%.2f\n", (unsigned long)VLAN_LEVEL_ARR[4],100*(float)VLAN_LEVEL_ARR[4]/(float)cumulative_stats.raw_packet_count);
    printf("\t|MPLSs Packets:                    |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.mpls_count,100*(float)cumulative_stats.mpls_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "MPLSs Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.mpls_count,100*(float)cumulative_stats.mpls_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|0 MPLS Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)MPLS_LEVEL_ARR[0],100*(float)MPLS_LEVEL_ARR[0]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "0 MPLS Level Packets,%llu,%.2f\n", (unsigned long)MPLS_LEVEL_ARR[0],100*(float)MPLS_LEVEL_ARR[0]/(float)cumulative_stats.raw_packet_count);
    printf("\t|1 MPLS Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)MPLS_LEVEL_ARR[1],100*(float)MPLS_LEVEL_ARR[1]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "1 MPLS Level Packets,%llu,%.2f\n", (unsigned long)MPLS_LEVEL_ARR[1],100*(float)MPLS_LEVEL_ARR[1]/(float)cumulative_stats.raw_packet_count);
    printf("\t|2 MPLS Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)MPLS_LEVEL_ARR[2],100*(float)MPLS_LEVEL_ARR[2]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "2 MPLS Level Packets,%llu,%.2f\n", (unsigned long)MPLS_LEVEL_ARR[2],100*(float)MPLS_LEVEL_ARR[2]/(float)cumulative_stats.raw_packet_count);
    printf("\t|3 MPLS Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)MPLS_LEVEL_ARR[3],100*(float)MPLS_LEVEL_ARR[3]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "3 MPLS Level Packets,%llu,%.2f\n", (unsigned long)MPLS_LEVEL_ARR[3],100*(float)MPLS_LEVEL_ARR[3]/(float)cumulative_stats.raw_packet_count);
    printf("\t|4 MPLS Level Packets:             |%-19llu |%6.2f    |\n", (unsigned long)MPLS_LEVEL_ARR[4],100*(float)MPLS_LEVEL_ARR[4]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "4 MPLS Level Packets,%llu,%.2f\n", (unsigned long)MPLS_LEVEL_ARR[4],100*(float)MPLS_LEVEL_ARR[4]/(float)cumulative_stats.raw_packet_count);
    printf("\t|PPPoE Packets:                    |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.pppoe_count,100*(float)cumulative_stats.pppoe_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "PPPoE Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.pppoe_count,100*(float)cumulative_stats.pppoe_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|Fragmented Packets:               |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.fragmented_count,100*(float)cumulative_stats.fragmented_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Fragmented Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.fragmented_count,100*(float)cumulative_stats.fragmented_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|Fragmented Packets with TCP:      |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.tcp_frag,100*(float)cumulative_stats.tcp_frag/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Fragmented Packets with TCP,%llu,%.2f\n", (unsigned long)cumulative_stats.tcp_frag,100*(float)cumulative_stats.tcp_frag/(float)cumulative_stats.raw_packet_count);
    printf("\t|Fragmented Packets with UDP:      |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.udp_frag,100*(float)cumulative_stats.udp_frag/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Fragmented Packets with UDP,%llu,%.2f\n", (unsigned long)cumulative_stats.udp_frag,100*(float)cumulative_stats.udp_frag/(float)cumulative_stats.raw_packet_count);
    printf("\t|Packet Len < 64:                  |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.packet_len[0],100*(float)cumulative_stats.packet_len[0]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Packet Len < 64,%llu,%.2f\n", (unsigned long)cumulative_stats.packet_len[0],100*(float)cumulative_stats.packet_len[0]/(float)cumulative_stats.raw_packet_count);
    printf("\t|Packet Len 64-128:                |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.packet_len[1],100*(float)cumulative_stats.packet_len[1]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Packet Len 64-128,%llu,%.2f\n", (unsigned long)cumulative_stats.packet_len[1],100*(float)cumulative_stats.packet_len[1]/(float)cumulative_stats.raw_packet_count);
    printf("\t|Packet Len 128-256:               |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.packet_len[2],100*(float)cumulative_stats.packet_len[2]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Packet Len 128-256,%llu,%.2f\n", (unsigned long)cumulative_stats.packet_len[2],100*(float)cumulative_stats.packet_len[2]/(float)cumulative_stats.raw_packet_count);
    printf("\t|Packet Len 256-1024:              |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.packet_len[3],100*(float)cumulative_stats.packet_len[3]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Packet Len 256-1024,%llu,%.2f\n", (unsigned long)cumulative_stats.packet_len[3],100*(float)cumulative_stats.packet_len[3]/(float)cumulative_stats.raw_packet_count);
    printf("\t|Packet Len 1024-1500:             |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.packet_len[4],100*(float)cumulative_stats.packet_len[4]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Packet Len 1024-1500,%llu,%.2f\n", (unsigned long)cumulative_stats.packet_len[4],100*(float)cumulative_stats.packet_len[4]/(float)cumulative_stats.raw_packet_count);
    printf("\t|Packet Len > 1500:                |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.packet_len[5],100*(float)cumulative_stats.packet_len[5]/(float)cumulative_stats.raw_packet_count);
    fprintf(f_general, "Packet Len > 1500,%llu,%.2f\n", (unsigned long)cumulative_stats.packet_len[5],100*(float)cumulative_stats.packet_len[5]/(float)cumulative_stats.raw_packet_count);
    printf("\t|Avg Packet Size in Bytes:         |%-19llu |          |\n", avg_pkt_size);
    fprintf(f_general, "Avg Packet Size in Bytes,%llu\n", avg_pkt_size);
    printf("\t|Unique flows:                     |%-19llu |%6.2f    |\n", cumulative_stats.ndpi_flow_count,100*(float)cumulative_stats.ndpi_flow_count/(float)cumulative_stats.ndpi_flow_count);
    fprintf(f_general, "Unique flows,%llu,%.2f\n", cumulative_stats.ndpi_flow_count,100*(float)cumulative_stats.ndpi_flow_count/(float)cumulative_stats.ndpi_flow_count);
    printf("\t|Single Side flows:                |%-19llu |%6.2f    |\n", cumulative_stats.ndpi_flow_count - single_side_flow_count,100*(float)(cumulative_stats.ndpi_flow_count - single_side_flow_count)/(float)cumulative_stats.ndpi_flow_count);
    fprintf(f_general, "Single Side flows,%llu,%.2f\n", cumulative_stats.ndpi_flow_count - single_side_flow_count,100*(float)(cumulative_stats.ndpi_flow_count - single_side_flow_count)/(float)cumulative_stats.ndpi_flow_count);
    total_flows = (float)(cumulative_stats.ndpi_flow_count + cumulative_stats.dup_flows);
    printf("\t|IPv4 Duplicated flows:            |%-19llu |%6.2f    |\n", (long long unsigned int)cumulative_stats.dup_flows,100*(float)cumulative_stats.dup_flows/total_flows);
    fprintf(f_general, "IPv4 Duplicated flows,%llu,%.2f\n", (long long unsigned int)cumulative_stats.dup_flows,100*(float)cumulative_stats.dup_flows/total_flows);
    printf("\t|HTTP Duplicated flows:            |%-19llu |%6.2f    |\n", (long long unsigned int)cumulative_stats.dup_http_flows,100*(float)cumulative_stats.dup_http_flows/total_flows);
    fprintf(f_general, "HTTP Duplicated flows,%llu,%.2f\n", (long long unsigned int)cumulative_stats.dup_http_flows,100*(float)cumulative_stats.dup_http_flows/total_flows);
    printf("\t|SSL Duplicated flows:             |%-19llu |%6.2f    |\n", (long long unsigned int)cumulative_stats.dup_ssl_flows,100*(float)cumulative_stats.dup_ssl_flows/total_flows);
    fprintf(f_general, "SSL Duplicated flows,%llu,%.2f\n", (long long unsigned int)cumulative_stats.dup_ssl_flows,100*(float)cumulative_stats.dup_ssl_flows/total_flows);
    printf("\t ------------------------------------------------------------------\n\n");
    printf("\nHttp Statistics:\n\n");
    printf("\t ------------------------------------------------------------------\n");
    printf("\t|Traffic statistics                |Value               |Precentage|\n");
    fprintf(f_http, "Traffic statistics,Value,Precentage\n");
    printf("\t ------------------------------------------------------------------\n");
    printf("\t|HTTP GET Packets:                 |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.http_get_count,100*(float)cumulative_stats.http_get_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_http, "HTTP GET Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.http_get_count,100*(float)cumulative_stats.http_get_count/(float)cumulative_stats.raw_packet_count);
    //printf("\t|HTTP GET / Gbps:                  |%-19.2f |         |\n", (unsigned long)cumulative_stats.http_get_count/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
    printf("\t|HTTP GET / Gbps:                  |%-19.2f |          |\n", (unsigned long)cumulative_stats.http_get_count/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)) );
    fprintf(f_http, "HTTP GET / Gbps,%.2f\n", (unsigned long)cumulative_stats.http_get_count/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
    printf("\t|AVG HTTP GET Size:                |%-19.0f |%6.2f    |\n", (float)cumulative_stats.http_avg_get_size/(float)cumulative_stats.http_get_count);
    fprintf(f_http, "AVG HTTP GET Size,%.0f,%.2f\n", (float)cumulative_stats.http_avg_get_size/(float)cumulative_stats.http_get_count);
    printf("\t|AVG GET Requests Per Flow:        |%-19.2f |          |\n",(float)cumulative_stats.http_get_count/total_http_flows);
    fprintf(f_http, "AVG GET Requests Per Flow,%-19.2f\n", (float)cumulative_stats.http_get_count/total_http_flows);
    printf("\t|HTTP POST Packets:                |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.http_post_count,100*(float)cumulative_stats.http_post_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_http, "HTTP POST Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.http_post_count,100*(float)cumulative_stats.http_post_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|HTTP POST / Gbps:                 |%-19.2f |          |\n", (unsigned long)cumulative_stats.http_post_count/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)) );
    fprintf(f_http, "HTTP POST / Gbps,%.2f\n", (unsigned long)cumulative_stats.http_post_count/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
    printf("\t|AVG HTTP POST Size:               |%-19.0f |%6.2f    |\n", (float)cumulative_stats.http_avg_post_size/(float)cumulative_stats.http_post_count);
    fprintf(f_http, "AVG HTTP POST Size,%.0f,%.2f\n", (float)cumulative_stats.http_avg_post_size/(float)cumulative_stats.http_post_count);
    printf("\t|AVG POST Requests Per Flow:       |%-19.2f |          |\n",(float)cumulative_stats.http_post_count/total_http_flows);
    fprintf(f_http, "AVG POST Requests Per Flow,%-19.2f\n", (float)cumulative_stats.http_post_count/total_http_flows);
    printf("\t|HTTP HEAD Packets:                |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.http_head_count,100*(float)cumulative_stats.http_head_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_http, "HTTP HEAD Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.http_head_count,100*(float)cumulative_stats.http_head_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|HTTP HEAD / Gbps:                 |%-19.2f |          |\n", (unsigned long)cumulative_stats.http_head_count/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
    fprintf(f_http, "HTTP HEAD / Gbps,%.2f\n", (unsigned long)cumulative_stats.http_head_count/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
    printf("\t|AVG HTTP HEAD Size:               |%-19.0f |%6.2f    |\n", (float)cumulative_stats.http_avg_head_size/(float)cumulative_stats.http_head_count);
    fprintf(f_http, "AVG HTTP HEAD Size,%.0f,%.2f\n", (float)cumulative_stats.http_avg_head_size/(float)cumulative_stats.http_head_count);
    printf("\t|AVG HEAD Requests Per Flow:       |%-19.2f |          |\n",(float)cumulative_stats.http_head_count/total_http_flows);
    fprintf(f_http, "AVG HEAD Requests Per Flow,%-19.2f\n", (float)cumulative_stats.http_head_count/total_http_flows);
    printf("\t ------------------------------------------------------------------\n\n");
    printf("\nSIGTRAN Statistics:\n\n");
    printf("\t ------------------------------------------------------------------\n");
    printf("\t|Traffic statistics                |Value               |Precentage|\n");
    fprintf(f_sig, "Traffic statistics,Value,Precentage\n");
    printf("\t ------------------------------------------------------------------\n");
    printf("\t|H248 Packets:                     |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.h248_count,100*(float)cumulative_stats.h248_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sig, "H248 Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.h248_count,100*(float)cumulative_stats.h248_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|SCCP Packets:                     |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.sccp_count,100*(float)cumulative_stats.sccp_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sig, "SCCP Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.sccp_count,100*(float)cumulative_stats.sccp_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|ISUP Packets:                     |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.isup_count,100*(float)cumulative_stats.isup_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sig, "ISUP Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.isup_count,100*(float)cumulative_stats.isup_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|BICC Packets:                     |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.bicc_count,100*(float)cumulative_stats.bicc_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sig, "BICC Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.bicc_count,100*(float)cumulative_stats.bicc_count/(float)cumulative_stats.raw_packet_count);
    printf("\t ------------------------------------------------------------------\n\n");
    printf("\nSIP Statistics:\n\n");
    printf("\t ------------------------------------------------------------------\n");
    printf("\t|Traffic statistics                |Value               |Precentage|\n");
    fprintf(f_sip, "Traffic statistics,Value,Precentage\n");
    printf("\t ------------------------------------------------------------------\n");
    printf("\t|SIP ACK Packets:                  |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.sip_ack_count,100*(float)cumulative_stats.sip_ack_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sip, "SIP ACK Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.sip_ack_count,100*(float)cumulative_stats.sip_ack_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|SIP BYE Packets:                  |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.sip_bye_count,100*(float)cumulative_stats.sip_bye_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sip, "SIP BYE Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.sip_bye_count,100*(float)cumulative_stats.sip_bye_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|SIP OPTIONS Packets:              |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.sip_options_count,100*(float)cumulative_stats.sip_options_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sip, "SIP OPTIONS Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.sip_options_count,100*(float)cumulative_stats.sip_options_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|SIP INVITE Packets:               |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.sip_invite_count,100*(float)cumulative_stats.sip_invite_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sip, "SIP INVITE Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.sip_invite_count,100*(float)cumulative_stats.sip_invite_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|SIP CANCEL Packets:               |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.sip_cancel_count,100*(float)cumulative_stats.sip_cancel_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sip, "SIP CANCEL Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.sip_cancel_count,100*(float)cumulative_stats.sip_cancel_count/(float)cumulative_stats.raw_packet_count);
    printf("\t|SIP PRACK Packets:                |%-19llu |%6.2f    |\n", (unsigned long)cumulative_stats.sip_prack_count,100*(float)cumulative_stats.sip_prack_count/(float)cumulative_stats.raw_packet_count);
    fprintf(f_sip, "SIP PRACK Packets,%llu,%.2f\n", (unsigned long)cumulative_stats.sip_prack_count,100*(float)cumulative_stats.sip_prack_count/(float)cumulative_stats.raw_packet_count);
    printf("\t ------------------------------------------------------------------\n\n");
   printf("\n\nPer Second New Flows Distribution:");
    int new_connection_counter = 0;
    int http_connection_counter = 0;
    int ssl_connection_counter = 0;
   printf("\n\n\t ------------------------------------------------------------------------\n");
       printf("\t|SEC        |Total New Flows      |HTTP New Flows         |SSL New Flows |\n");
       fprintf(f_persecnewflow, "SEC,Total New Flows,HTTP New Flows,SSL New Flows\n");
       printf("\t ------------------------------------------------------------------------\n");
    for (new_connection_counter = 0; new_connection_counter < (int)traffic_duration_all_sec; new_connection_counter++,http_connection_counter++,ssl_connection_counter++){
    	printf ("\t|%-10d |%-21d|%-23d|%-12d  |\n",new_connection_counter,NEW_CONNECTIONS_ARR[new_connection_counter],HTTP_CONNECTIONS_ARR[http_connection_counter],SSL_CONNECTIONS_ARR[ssl_connection_counter]);
    	fprintf (f_persecnewflow, "%d,%d,%d,%d\n",new_connection_counter,NEW_CONNECTIONS_ARR[new_connection_counter],HTTP_CONNECTIONS_ARR[http_connection_counter],SSL_CONNECTIONS_ARR[ssl_connection_counter]);
      //if(SSL_CONNECTIONS_ARR[ssl_connection_counter] > 0)
//    	printf ("\tSSL Connction  SEC %d:             %-13d %13.2f\%\n",ssl_connection_counter, SSL_CONNECTIONS_ARR[ssl_connection_counter],100*(float)SSL_CONNECTIONS_ARR[ssl_connection_counter]/(float)cumulative_stats.ndpi_flow_count);
    }
   printf    ("\t -----------------------------------------------------------------------\n\n");
    //if(enable_protocol_guess)
    //  printf("\tGuessed flow protos:\t\t  %-13u\n", cumulative_stats.guessed_flow_protocols);

  } else {
#ifdef HAVE_JSON_C
    if((json_fp = fopen(_jsonFilePath,"w")) == NULL) {
      printf("Error create .json file\n");
      json_flag = 0;
    } else {
      jObj_main = json_object_new_object();
      jObj_trafficStats = json_object_new_object();
      jArray_detProto = json_object_new_array();

      json_object_object_add(jObj_trafficStats,"ethernet.bytes",json_object_new_int64(cumulative_stats.total_wire_bytes));
      json_object_object_add(jObj_trafficStats,"discarded.bytes",json_object_new_int64(cumulative_stats.total_discarded_bytes));
      json_object_object_add(jObj_trafficStats,"ip.packets",json_object_new_int64(cumulative_stats.ip_packet_count));
      json_object_object_add(jObj_trafficStats,"total.packets",json_object_new_int64(cumulative_stats.raw_packet_count));
      json_object_object_add(jObj_trafficStats,"ip.bytes",json_object_new_int64(cumulative_stats.total_ip_bytes));
      json_object_object_add(jObj_trafficStats,"avg.pkt.size",json_object_new_int(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count));
      json_object_object_add(jObj_trafficStats,"unique.flows",json_object_new_int(cumulative_stats.ndpi_flow_count));
      json_object_object_add(jObj_trafficStats,"tcp.pkts",json_object_new_int64(cumulative_stats.tcp_count));
      json_object_object_add(jObj_trafficStats,"udp.pkts",json_object_new_int64(cumulative_stats.udp_count));
      json_object_object_add(jObj_trafficStats,"vlan.pkts",json_object_new_int64(cumulative_stats.vlan_count));
      json_object_object_add(jObj_trafficStats,"mpls.pkts",json_object_new_int64(cumulative_stats.mpls_count));
      json_object_object_add(jObj_trafficStats,"pppoe.pkts",json_object_new_int64(cumulative_stats.pppoe_count));
      json_object_object_add(jObj_trafficStats,"fragmented.pkts",json_object_new_int64(cumulative_stats.fragmented_count));
      json_object_object_add(jObj_trafficStats,"max.pkt.size",json_object_new_int(cumulative_stats.max_packet_len));
      json_object_object_add(jObj_trafficStats,"pkt.len_min64",json_object_new_int64(cumulative_stats.packet_len[0]));
      json_object_object_add(jObj_trafficStats,"pkt.len_64_128",json_object_new_int64(cumulative_stats.packet_len[1]));
      json_object_object_add(jObj_trafficStats,"pkt.len_128_256",json_object_new_int64(cumulative_stats.packet_len[2]));
      json_object_object_add(jObj_trafficStats,"pkt.len_256_1024",json_object_new_int64(cumulative_stats.packet_len[3]));
      json_object_object_add(jObj_trafficStats,"pkt.len_1024_1500",json_object_new_int64(cumulative_stats.packet_len[4]));
      json_object_object_add(jObj_trafficStats,"pkt.len_grt1500",json_object_new_int64(cumulative_stats.packet_len[5]));
      json_object_object_add(jObj_trafficStats,"guessed.flow.protos",json_object_new_int(cumulative_stats.guessed_flow_protocols));

      json_object_object_add(jObj_main,"traffic.statistics",jObj_trafficStats);
    }
#endif
  }

int protocol_id[200]={0}, j=0, c, d, swap_id;
float protocol_bps[200]={0.0}, swap_bps, t_duration;
/*if (live_capture) t_duration = last_flowendtime - (float)analysis_start_time_usec;
else t_duration = (pcap_end.tv_sec*1000000 + pcap_end.tv_usec) - (pcap_start.tv_sec*1000000 + pcap_start.tv_usec);
*/
  for(i = 0; i <= ndpi_get_num_supported_protocols(ndpi_thread_info[0].ndpi_struct); i++) {
    if(cumulative_stats.protocol_counter[i] > 0) {
      if(!json_flag) {
        protocol_id[i]=i;
        protocol_bps[i]=8*(( float )cumulative_stats.protocol_counter_bytes[i])/(float)tot_usec;

      }
    }
  }

  for (c = 0 ; c < ( ndpi_get_num_supported_protocols(ndpi_thread_info[0].ndpi_struct) - 1 ); c++)
  {
    for (d = 0 ; d < ndpi_get_num_supported_protocols(ndpi_thread_info[0].ndpi_struct) - c - 1; d++)
    {
      if (protocol_bps[d] < protocol_bps[d+1]) /* For decreasing order use < */
      {
        swap_bps       = protocol_bps[d];
        protocol_bps[d]   = protocol_bps[d+1];
        protocol_bps[d+1] = swap_bps;
        swap_id       = protocol_id[d];
        protocol_id[d]   = protocol_id[d+1];
        protocol_id[d+1] = swap_id;

      }
    }
  }
for (i = 0 ; i < 200 ; i++){
        if (protocol_id[i] > 0){
                j++;
        }
}


//  for ( c = 0 ; c < ndpi_get_num_supported_protocols(ndpi_thread_info[0].ndpi_struct) ; c++ )
//     printf("last packet time  %llu\n", last_flowendtime);
//     printf("traffic start time  %llu\n", analysis_start_time_usec);
//     printf("traffic duration time  %llu\n", last_flowendtime - analysis_start_time_usec);


  if(!json_flag) printf("\n\nDetected protocols:\n");
//  for(i = 0; i <= ndpi_get_num_supported_protocols(ndpi_thread_info[0].ndpi_struct); i++) {
  ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_thread_info[0].ndpi_struct, i);
  printf("\n\n   --------------------------------------------------------------------------------------------------------------\n");
  printf("  |PROTOCOLS            |PACKETS       |BITS          |\%BITS         |MBPS          |FLOWS         |FLOWS/Gbps   |\n");
  fprintf(f_protocols, "PROTOCOLS,PACKETS,BITS,\%BITS,MBPS,FLOWS,FLOWS/Gbps\n");
  printf("   --------------------------------------------------------------------------------------------------------------\n");
  for(i = 0; i <= j; i++) {
    if(cumulative_stats.protocol_counter[protocol_id[i]] > 0) {
      breed_stats[breed] += (long long unsigned int)cumulative_stats.protocol_counter_bytes[i];
      if(!json_flag) {
        printf("  |%-20s |%-13llu |%-13llu |%-13.3f |%-13.3f |%-13u |%-13.0f|\n",
               ndpi_get_proto_name(ndpi_thread_info[0].ndpi_struct, protocol_id[i]),
               (long long unsigned int)cumulative_stats.protocol_counter[protocol_id[i]],
               (long long unsigned int)cumulative_stats.protocol_counter_bytes[protocol_id[i]]*8,
               100*(( float )cumulative_stats.protocol_counter_bytes[protocol_id[i]])/(float)cumulative_stats.total_ip_bytes,
               8*(( float )cumulative_stats.protocol_counter_bytes[protocol_id[i]])/(last_flowendtime - analysis_start_time_usec),
               cumulative_stats.protocol_flows[protocol_id[i]],
               //cumulative_stats.protocol_flows[protocol_id[i]]/((8*(( float )cumulative_stats.protocol_counter_bytes[protocol_id[i]])/(last_flowendtime - analysis_start_time_usec))/1000));
               cumulative_stats.protocol_flows[protocol_id[i]]/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
               //cumulative_stats.protocol_flows[protocol_id[i]]/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000) ));
	
        fprintf(f_protocols,"%s,%llu,%llu,%.3f,%.3f,%u,%.0f\n",
               ndpi_get_proto_name(ndpi_thread_info[0].ndpi_struct, protocol_id[i]),
               (long long unsigned int)cumulative_stats.protocol_counter[protocol_id[i]],
               (long long unsigned int)cumulative_stats.protocol_counter_bytes[protocol_id[i]]*8,
               100*(( float )cumulative_stats.protocol_counter_bytes[protocol_id[i]])/(float)cumulative_stats.total_ip_bytes,
               8*(( float )cumulative_stats.protocol_counter_bytes[protocol_id[i]])/(last_flowendtime - analysis_start_time_usec),
               cumulative_stats.protocol_flows[protocol_id[i]],
               //cumulative_stats.protocol_flows[protocol_id[i]]/((8*(( float )cumulative_stats.protocol_counter_bytes[protocol_id[i]])/(last_flowendtime - analysis_start_time_usec))/1000));
               cumulative_stats.protocol_flows[protocol_id[i]]/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000) ));

      } else {
#ifdef HAVE_JSON_C
	jObj = json_object_new_object();

	json_object_object_add(jObj,"name",json_object_new_string(ndpi_get_proto_name(ndpi_thread_info[0].ndpi_struct, i)));
	json_object_object_add(jObj,"breed",json_object_new_string(ndpi_get_proto_breed_name(ndpi_thread_info[0].ndpi_struct, breed)));
	json_object_object_add(jObj,"packets",json_object_new_int64(cumulative_stats.protocol_counter[i]));
	json_object_object_add(jObj,"bytes",json_object_new_int64(cumulative_stats.protocol_counter_bytes[i]));
	json_object_object_add(jObj,"flows",json_object_new_int(cumulative_stats.protocol_flows[i]));

	json_object_array_add(jArray_detProto,jObj);
#endif
      }

      total_flow_bytes += cumulative_stats.protocol_counter_bytes[i];
    }
  }
  printf    ("   --------------------------------------------------------------------------------------------------------------\n");

/*  if(!json_flag) {
    printf("\n\nProtocol statistics:\n");

    for(i=0; i < NUM_BREEDS; i++) {
      if(breed_stats[i] > 0) {
	printf("\t%-20s %13llu bytes\n",
	       ndpi_get_proto_breed_name(ndpi_thread_info[0].ndpi_struct, i),
	       breed_stats[i]);
      }
    }
  }
*/
  printf("\n\nVLAN statistics:\n");
  for(i = 0; i < 4096; i++)
   {
      if(cumulative_stats.vlan_ids_count[i] != 0)
      {
        double prec = (cumulative_stats.vlan_ids_count[i]*100)/total_vlan;
        printf("\t [VLAN id: %d\t | Num of use: %d\t | %.2f%] \n",i,cumulative_stats.vlan_ids_count[i], prec);
      }
   }
  printf("\n\n");
  // printf("\n\nTotal Flow Traffic: %llu (diff: %llu)\n", total_flow_bytes, cumulative_stats.total_ip_bytes-total_flow_bytes);

  if(verbose) {
    if(!json_flag) printf("\n");

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_print_known_proto_walker, &thread_id);
    }

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      if(ndpi_thread_info[thread_id].stats.protocol_counter[0 /* 0 = Unknown */] > 0) {
        if(!json_flag) {
          //printf("\n\nUndetected flows:%s\n", undetected_flows_deleted ? " (expired flows are not listed below)" : "");
        }

        if(json_flag)
          json_flag = 2;
        break;
      }
    }

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      if(ndpi_thread_info[thread_id].stats.protocol_counter[0] > 0) {
        for(i=0; i<NUM_ROOTS; i++)
          ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_print_unknown_proto_walker, &thread_id);

      }
    }
//	  printf("Closure statistics:\n");
//	  printf("\tnumber of duplicated:%-13d%-13.4f\n",num_of_duplicated_pckts,100*(float)num_of_duplicated_pckts/(float)cumulative_stats.ndpi_flow_count);
//	  printf("\tnumber of single side:%-13d%-13.4f\n",num_of_single_side, 100*(float)num_of_single_side/(float)cumulative_stats.ndpi_flow_count);
  }

  if(json_flag != 0) {
#ifdef HAVE_JSON_C
    json_object_object_add(jObj_main,"detected.protos",jArray_detProto);
    json_object_object_add(jObj_main,"known.flows",jArray_known_flows);

    if(json_object_array_length(jArray_unknown_flows) != 0)
      json_object_object_add(jObj_main,"unknown.flows",jArray_unknown_flows);

    fprintf(json_fp,"%s\n",json_object_to_json_string(jObj_main));
    fclose(json_fp);
#endif
  }
}

/* ***************************************************** */

static void closePcapFile(u_int16_t thread_id) {
  if(ndpi_thread_info[thread_id]._pcap_handle != NULL) {
    pcap_close(ndpi_thread_info[thread_id]._pcap_handle);
  }
}

/* ***************************************************** */

static void breakPcapLoop(u_int16_t thread_id) {
  if(ndpi_thread_info[thread_id]._pcap_handle != NULL) {
    pcap_breakloop(ndpi_thread_info[thread_id]._pcap_handle);
  }
}

/* ***************************************************** */

// executed for each packet in the pcap file
void sigproc(int sig) {
  static int called = 0;
  int thread_id;

  if(called) return; else called = 1;
  shutdown_app = 1;

  for(thread_id=0; thread_id<num_threads; thread_id++)
    breakPcapLoop(thread_id);
}

/* ***************************************************** */

static int getNextPcapFileFromPlaylist(u_int16_t thread_id, char filename[], u_int32_t filename_len) {

  if(playlist_fp[thread_id] == NULL) {
    if((playlist_fp[thread_id] = fopen(_pcap_file[thread_id], "r")) == NULL)
      return -1;
  }

 next_line:
  if(fgets(filename, filename_len, playlist_fp[thread_id])) {
    int l = strlen(filename);
    if(filename[0] == '\0' || filename[0] == '#') goto next_line;
    if(filename[l-1] == '\n') filename[l-1] = '\0';
    return 0;
  } else {
    fclose(playlist_fp[thread_id]);
    playlist_fp[thread_id] = NULL;
    return -1;
  }
}

/* ***************************************************** */

static void configurePcapHandle(u_int16_t thread_id) {
  ndpi_thread_info[thread_id]._pcap_datalink_type = pcap_datalink(ndpi_thread_info[thread_id]._pcap_handle);

  if(_bpf_filter != NULL) {
    struct bpf_program fcode;

    if(pcap_compile(ndpi_thread_info[thread_id]._pcap_handle, &fcode, _bpf_filter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id]._pcap_handle));
    } else {
      if(pcap_setfilter(ndpi_thread_info[thread_id]._pcap_handle, &fcode) < 0) {
        printf("pcap_setfilter error: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id]._pcap_handle));
      } else
        printf("Successfully set BPF filter to '%s'\n", _bpf_filter);
    }
  }
}

/* ***************************************************** */

static void openPcapFileOrDevice(u_int16_t thread_id) {
  u_int snaplen = 1536;
  int promisc = 1;
  char errbuf[PCAP_ERRBUF_SIZE];

  /* trying to open a live interface */
  if((ndpi_thread_info[thread_id]._pcap_handle = pcap_open_live(_pcap_file[thread_id], snaplen, promisc, 500, errbuf)) == NULL) {
    capture_for = capture_until = 0;

    live_capture = 0;
    num_threads = 1; /* Open pcap files in single threads mode */

    /* trying to open a pcap file */
    if((ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(_pcap_file[thread_id], ndpi_thread_info[thread_id]._pcap_error_buffer)) == NULL) {
      char filename[256];

      /* trying to open a pcap playlist */
      if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) != 0 ||
         (ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(filename, ndpi_thread_info[thread_id]._pcap_error_buffer)) == NULL) {

        printf("ERROR: could not open pcap file or playlist: %s\n", ndpi_thread_info[thread_id]._pcap_error_buffer);
        exit(-1);
      } else {
        if(!json_flag) printf("Reading packets from playlist %s...\n", _pcap_file[thread_id]);
      }
    } else {
      if(!json_flag) printf("Reading packets from pcap file %s...\n", _pcap_file[thread_id]);
    }
  } else {
    live_capture = 1;

    if(!json_flag) printf("Capturing live traffic from device %s...\n", _pcap_file[thread_id]);
  }

  configurePcapHandle(thread_id);

  if(capture_for > 0) {
    if(!json_flag) printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_for);

#ifndef WIN32
    alarm(capture_for);
    signal(SIGALRM, sigproc);
#endif
  }
}

/* ***************************************************** */

static void pcap_packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  const struct ndpi_ethhdr *ethernet;
  struct ndpi_iphdr *iph;
  struct ndpi_ip6_hdr *iph6;
  u_int64_t time;
  u_int16_t type, ip_offset, ip_len;
  u_int16_t frag_off = 0, vlan_id = 0;
  u_int8_t proto = 0, vlan_packet = 0, vlan_level = 0, mpls_level = 0;
  u_int16_t thread_id = *((u_int16_t*)args);

  // printf("[ndpiReader] pcap_packet_callback : [%u.%u.%u.%u.%u -> %u.%u.%u.%u.%u]\n", ethernet->h_dest[1],ethernet->h_dest[2],ethernet->h_dest[3],ethernet->h_dest[4],ethernet->h_dest[5],ethernet->h_source[1],ethernet->h_source[2],ethernet->h_source[3],ethernet->h_source[4],ethernet->h_source[5]);
  ndpi_thread_info[thread_id].stats.raw_packet_count++;

  if((capture_until != 0) && (header->ts.tv_sec >= capture_until)) {
    if(ndpi_thread_info[thread_id]._pcap_handle != NULL)
      pcap_breakloop(ndpi_thread_info[thread_id]._pcap_handle);

    return;
  }

  if (!live_capture) {
    if (!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
    pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;
  }
    if(analysis_start_time == 0) {
	analysis_start_time = header->ts.tv_sec;
	analysis_start_time_usec = header->ts.tv_sec*1000000 + header->ts.tv_usec;
    }

  time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
    header->ts.tv_usec / (1000000 / detection_tick_resolution);

  if(ndpi_thread_info[thread_id].last_time > time) { /* safety check */
    // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_thread_info[thread_id].last_time - time);
    time = ndpi_thread_info[thread_id].last_time;
  }
  ndpi_thread_info[thread_id].last_time = time;

  if(ndpi_thread_info[thread_id]._pcap_datalink_type == DLT_NULL) 
  {
    if(ntohl(*((u_int32_t*)packet)) == 2)
      type = ETH_P_IP;
    else
      type = 0x86DD; /* IPv6 */

    ip_offset = 4;
  } 
  else if(ndpi_thread_info[thread_id]._pcap_datalink_type == DLT_EN10MB) 
  {
    ethernet = (struct ndpi_ethhdr *) packet;
    ip_offset = sizeof(struct ndpi_ethhdr);
    type = ntohs(ethernet->h_proto);
    //printf("dest: [%x:%x:%x:%x:%x:%x] src: [%x:%x:%x:%x:%x:%x] \n", ethernet->h_dest[0], ethernet->h_dest[1], ethernet->h_dest[2], ethernet->h_dest[3]
    //        ,ethernet->h_dest[4], ethernet->h_dest[5], ethernet->h_dest[6], ethernet->h_source[0], ethernet->h_source[1], ethernet->h_source[2]
    //        ,ethernet->h_source[3], ethernet->h_source[4],ethernet->h_source[5], ethernet->h_source[6]);
  } 
  else if(ndpi_thread_info[thread_id]._pcap_datalink_type == 113 /* Linux Cooked Capture */) 
  {
    type = (packet[14] << 8) + packet[15];
    ip_offset = 16;
  } else
    return;

  while(1) 
  {
    if(type == 0x8100 /* VLAN */) 
    {
      vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
      type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];    
      ndpi_thread_info[thread_id].stats.vlan_level_count[vlan_level] += 1;
      vlan_level += 1;
      ndpi_thread_info[thread_id].stats.vlan_ids_count[vlan_id] += 1; 
      ip_offset += 4;
      vlan_packet = 1;
    } 
    else if(type == 0x8847 /* MPLS */) 
    {
      u_int32_t label = ntohl(*((u_int32_t*)&packet[ip_offset]) );

      ndpi_thread_info[thread_id].stats.mpls_count++;
      type = 0x800, ip_offset += 4;
          
      mpls_level += 1 ;

      while((label & 0x100) != 0x100) {
        mpls_level += 1 ;
        label = ntohl(*((u_int32_t*)&packet[ip_offset]) );
        ip_offset += 4;
      }
      ndpi_thread_info[thread_id].stats.mpls_level_count[mpls_level] += 1;
    } else if(type == 0x8864 /* PPPoE */) {
      ndpi_thread_info[thread_id].stats.pppoe_count++;
      type = 0x0800;
      ip_offset += 8;
    } else if(type == 0x86DD /* IPV6 */) {
      ipv6_counter++;
      break;
    } else if(type != 0x8100 && type != 0x0800 &&  type != 0x8864  &&  type != 0x8847 ) {
        ETHER_TYPE_ARR[(int)type]++;
        break;
    } else
      break;
  }
VLAN_LEVEL_ARR[vlan_level]++;
MPLS_LEVEL_ARR[mpls_level]++;
ndpi_thread_info[thread_id].stats.vlan_count += vlan_packet;
  iph = (struct ndpi_iphdr *) &packet[ip_offset];

  // just work on Ethernet packets that contain IP
  if(type == ETH_P_IP && header->caplen >= ip_offset) 
  {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
    if(header->caplen < header->len) {
      static u_int8_t cap_warning_used = 0;

      if(cap_warning_used == 0) 
	  {
	if(!json_flag) printf("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
	cap_warning_used = 1;
      }
    }
  }

  if(iph->version == 4) 
  {
    ip_len = ((u_short)iph->ihl * 4);
    iph6 = NULL;
    
    if((frag_off & 0x3FFF) != 0) 
    {
      static u_int8_t ipv4_frags_warning_used = 0;

    if(iph->protocol == 6)
    {   //tcp
        ndpi_thread_info[thread_id].stats.tcp_frag++;
    }
    else if(iph->protocol == 17)
    {   //udp
        ndpi_thread_info[thread_id].stats.udp_frag++;
    }
    v4_frags_warning:
      ndpi_thread_info[thread_id].stats.fragmented_count++;
      if(ipv4_frags_warning_used == 0) {
        ipv4_frags_warning_used = 1;
      }

      ndpi_thread_info[thread_id].stats.total_discarded_bytes +=  header->len;
      return;
    }
  } else if(iph->version == 6) {
    iph6 = (struct ndpi_ip6_hdr *)&packet[ip_offset];
    proto = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    ip_len = sizeof(struct ndpi_ip6_hdr);
    iph = NULL;
  } else {
    static u_int8_t ipv4_warning_used = 0;

  v4_warning:
    if(ipv4_warning_used == 0) {
      if(!json_flag)/* printf("\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");*/
      ipv4_warning_used = 1;
    }

    ndpi_thread_info[thread_id].stats.total_discarded_bytes +=  header->len;
    return;
  }

  if(decode_tunnels && (proto == IPPROTO_UDP)) {
    struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
    u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

    if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
      /* Check if it's GTPv1 */
      u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
      u_int8_t flags = packet[offset];
      u_int8_t message_type = packet[offset+1];

      if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
        ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;
        if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
        if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
        if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

        iph = (struct ndpi_iphdr *) &packet[ip_offset];

        if(iph->version != 4) {
          // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)ndpi_thread_info[thread_id].stats.raw_packet_count);
          goto v4_warning;
        }
      }
    }
  }

  // process the packet
  //printf("thread id:%d time:%d vlan_id:%d iph:%d \n",thread_id, time, vlan_id, iph);
  pcap_dumper_t *dumper = NULL;
  //printMacAddresses(ethernet->h_source, ethernet->h_dest);
  packet_processing(thread_id, time, vlan_id, iph, iph6, ip_offset, header->len - ip_offset, header->len, &header->ts, &dumper, ethernet->h_source, ethernet->h_dest);
  if(dumper!=NULL)
  {
	//Add packet to file
	pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)header, packet);

  }

}

/* ******************************************************************** */

static void runPcapLoop(u_int16_t thread_id) {
  if((!shutdown_app) && (ndpi_thread_info[thread_id]._pcap_handle != NULL))
    pcap_loop(ndpi_thread_info[thread_id]._pcap_handle, -1, &pcap_packet_callback, (u_char*)&thread_id);
}

/* ******************************************************************** */

void *processing_thread(void *_thread_id) {
  long thread_id = (long) _thread_id;

#ifdef linux
  if(core_affinity[thread_id] >= 0) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_affinity[thread_id], &cpuset);

    if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
    else {
		if(!json_flag) printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
    }
  } else
#endif
    if(!json_flag) printf("Running thread %ld...\n", thread_id);

 pcap_loop:
  runPcapLoop(thread_id);

  if(playlist_fp[thread_id] != NULL) { /* playlist: read next file */
    char filename[256];

    if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) == 0 &&
       (ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(filename, ndpi_thread_info[thread_id]._pcap_error_buffer)) != NULL) {
      configurePcapHandle(thread_id);
      goto pcap_loop;
    }
  }

  return NULL;
}

/* ******************************************************************** */

void test_lib() {
  struct timeval begin, end;
  u_int64_t tot_usec;
  long thread_id;

#ifdef HAVE_JSON_C
  json_init();
#endif

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    setupDetection(thread_id);
    openPcapFileOrDevice(thread_id);
  }

  gettimeofday(&begin, NULL);

  /* Running processing threads */
  for(thread_id = 0; thread_id < num_threads; thread_id++)
    pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);

  /* Waiting for completion */
  for(thread_id = 0; thread_id < num_threads; thread_id++) 
    pthread_join(ndpi_thread_info[thread_id].pthread, NULL);

  gettimeofday(&end, NULL);
  tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);

  /* Printing cumulative results */
  printResults(tot_usec);

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    closePcapFile(thread_id);
    terminateDetection(thread_id);
  }
}

/* ***************************************************** */

int main(int argc, char **argv) {
  int i;
  FILE *f_conn;
  struct timeval bgn;
  char dir_name[40];
  gettimeofday(&bgn, NULL);
  sprintf(dir_name, "/tmp/res_%d", bgn.tv_sec);
  mkdir(dir_name, 0777);

  memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));
  memset(&pcap_start, 0, sizeof(pcap_start));
  memset(&pcap_end, 0, sizeof(pcap_end));
  parseOptions(argc, argv);


/*  if(!json_flag) {
    printf("Using ps_analyzer (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);
  }
*/

  //system("killall -9 /usr/local/bin/hslb_d &> /dev/null &");
  //system("/usr/local/bin/hslb_d  -i dna0,dna1 -c 1000 -m 4 -n 10 -d");
  //system("sleep 5");
  
  signal(SIGINT, sigproc);
  
  int hs_check = system("ps -ef|grep hsl|grep -v grep|wc -l");
  printf("the HSLB module runs \n");
  system("echo 'Traffic Statistic,Value' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/connection_stats.csv)");
  char conncsvname[100];
  sprintf(conncsvname, "%s/connection_stats_tmp.csv", dir_name);
  f_conn = fopen(conncsvname, "w");
  
  system("echo 'Repeatitions,Request/Response,Content-Type' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_content_type_sorted.csv)");
  char sipcontenttypecsvname[100];
  sprintf(sipcontenttypecsvname, "%s/sip_content_type_stats.csv", dir_name);
  f_sip_content_type = fopen(sipcontenttypecsvname, "w");
  
  system("echo 'Repeatitions,Request/Response,Codec' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_codecs_stats_sorted.csv)");
  char sipcodeckcsvname[100];
  sprintf(sipcodeckcsvname, "%s/sip_codecs_stats.csv", dir_name);
  f_sip_codecs = fopen(sipcodeckcsvname, "w");
  
  system("echo 'Repeatitions,Request/Response,IP1,IP2' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/request_response_per_sip_peer_stats.csv)");
  char persippeername[100];
  sprintf(persippeername, "%s/request_response_per_sip_peer_stats_tmp.csv", dir_name);
  f_per_sip_peer = fopen(persippeername, "w");
  
  system("echo 'L4Protocol,IP1,port1,IP2,port2,Vlan,Protocol #,Protocol Name,Packets,Bytes' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_rtp_connection_list.csv)");
  char connectionlistcsvname[100];
  sprintf(connectionlistcsvname, "%s/sip_rtp_connection_list.csv", dir_name);
  f_connection = fopen(connectionlistcsvname, "a");

  system("echo 'Repeatitions,Protocol,IP' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_ip_list.csv)");
  char sipiplistcsvname[100];
  sprintf(sipiplistcsvname, "%s/sip_ip_list_tmp.csv", dir_name);
  f_sip_ip_list = fopen(sipiplistcsvname, "a");

  system("echo 'Repeatitions,Protocol,IP1,IP2' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_couple_list.csv)");
  char sipcouplelistcsvname[100];
  sprintf(sipcouplelistcsvname, "%s/sip_couple_list_tmp.csv", dir_name);
  f_sip_couple_list = fopen(sipcouplelistcsvname, "a");

  system("echo 'Repeatitions,IP' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/ip_list.csv)");
  char iplistcsvname[100];
  sprintf(iplistcsvname, "%s/ip_list_tmp.csv", dir_name);
  f_ips_list = fopen(iplistcsvname, "a");

  char generalcsvname[100];
  sprintf(generalcsvname, "%s/general_stats.csv", dir_name);
  f_general = fopen(generalcsvname, "w");

  char httpcsvname[100];
  sprintf(httpcsvname, "%s/http_stats.csv", dir_name);
  f_http = fopen(httpcsvname, "w");

  char sipcsvname[100];
  sprintf(sipcsvname, "%s/sip_request_type_stats.csv", dir_name);
  f_sip = fopen(sipcsvname, "w");

  char sigcsvname[100];
  sprintf(sigcsvname, "%s/sigtran_stats.csv", dir_name);
  f_sig = fopen(sigcsvname, "w");

  char persecnewflowcsvname[100];
  sprintf(persecnewflowcsvname, "%s/per_sec_new_flow_stats.csv", dir_name);
  f_persecnewflow = fopen(persecnewflowcsvname, "w");

  char protocolscsvname[100];
  sprintf(protocolscsvname, "%s/protocols.csv", dir_name);
  f_protocols = fopen(protocolscsvname, "w"); 	

  for(i=0; i<num_loops; i++)
    test_lib();
    printf("\nConnections Statistics:\n\n");
    if(total_tcp_flows){
    	printf("\tAvg TCP Flow Duration(sec):                %-13.3f\n", tcp_connection_duration/total_tcp_flows);
    	fprintf(f_conn, "Avg TCP Flow Duration(sec),%.3f\n", tcp_connection_duration/total_tcp_flows);
    	printf("\tAvg TCP Flow Duration(Bytes):              %-13.3f\n", tcp_connection_size_bytes/total_tcp_flows);
    	fprintf(f_conn, "Avg TCP Flow Duration(Bytes),%.3f\n", tcp_connection_size_bytes/total_tcp_flows);
    	printf("\tTotal TCP Flow Duration(sec):              %-13.3f\n", tcp_connection_duration);
    	fprintf(f_conn, "Total TCP Flow Duration(sec),%.3f\n", tcp_connection_duration);
    	printf("\tTotal TCP flows:                           %-13llu \n", (long long unsigned int)total_tcp_flows);
    	fprintf(f_conn, "Total TCP flows,%llu\n", (long long unsigned int)total_tcp_flows);
    	printf("\tTotal TCP Bytes:                           %-13llu \n", (long long unsigned int)tcp_connection_size_bytes);
    	fprintf(f_conn, "Total TCP Bytes,%llu\n", (long long unsigned int)tcp_connection_size_bytes);
    }
    if(total_udp_flows){
    	printf("\tAvg UDP Flow Duration(sec):                %-13.3f\n", udp_connection_duration/total_udp_flows);
    	fprintf(f_conn, "Avg UDP Flow Duration(sec),%.3f\n", udp_connection_duration/total_udp_flows);
    	printf("\tAvg UDP Flow Duration(Bytes):              %-13.3f\n", udp_connection_size_bytes/total_udp_flows);
    	fprintf(f_conn, "Avg UDP Flow Duration(bytes),%.3f\n", udp_connection_size_bytes/total_udp_flows);
    	printf("\tTotal UDP Flow Duration(sec):              %-13.3f\n", udp_connection_duration);
    	fprintf(f_conn, "Total UDP Flow Duration(sec),%.3f\n", udp_connection_duration);
    	printf("\tTotal UDP flows:                           %-13llu \n", (long long unsigned int)total_udp_flows);
    	fprintf(f_conn,"Total UDP flows,%llu\n", (long long unsigned int)total_udp_flows);
    	printf("\tTotal UDP Bytes:                           %-13llu \n", (long long unsigned int)udp_connection_size_bytes);
    	fprintf(f_conn,"Total UDP Bytes,%llu\n", (long long unsigned int)udp_connection_size_bytes);
    }
    if(total_http_flows){
    	printf("\tAvg HTTP Flow Duration(sec):               %-13.3f\n", http_connection_duration/total_http_flows);
    	fprintf(f_conn, "Avg HTTP Flow Duration(sec),%.3f\n", http_connection_duration/total_http_flows);
    	printf("\tTotal HTTP Flow Duration(sec):             %-13.3f\n", http_connection_duration);
    	fprintf(f_conn, "Total HTTP Flow Duration(sec),%.3f\n", http_connection_duration);
    	printf("\tAvg HTTP Flow Size in Bytes:               %-13.3f\n", http_connection_size_bytes/total_http_flows);
    	fprintf(f_conn, "Avg HTTP Flow Size in Bytes,%.3f\n", http_connection_size_bytes/total_http_flows);
    	printf("\tTotal HTTP flows(80):                      %-13llu \n", (long long unsigned int)total_http_flows);
    	fprintf(f_conn, "Total HTTP flows(80),%llu\n", (long long unsigned int)total_http_flows);
    	printf("\tTotal HTTP Bytes:                          %-13llu \n", (long long unsigned int)http_connection_size_bytes);
    	fprintf(f_conn,"Total HTTP Bytes,%llu\n", (long long unsigned int)http_connection_size_bytes);
    	printf("\tHTTP Flows / Gbps(80):                     %-13.3f \n", (float)total_http_flows/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)) );
    	fprintf(f_conn, "HTTP Flows / Gbps(80),%.3f \n", (float)total_http_flows/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
    }
    if(total_ssl_flows){
    	printf("\tAvg SSL Flow Duration(sec):                %-13.3f\n", ssl_connection_duration/total_ssl_flows);
    	fprintf(f_conn, "Avg SSL Flow Duration(sec),%.3f\n", ssl_connection_duration/total_ssl_flows);
    	printf("\tTotal SSL Flow Duration(sec):              %-13.3f\n", ssl_connection_duration);
    	fprintf(f_conn, "Total SSL Flow Duration(sec),%.3f\n", ssl_connection_duration);
    	printf("\tAvg SSL Flow Size in Bytes:                %-13.3f\n", ssl_connection_size_bytes/total_ssl_flows);
    	fprintf(f_conn, "Avg SSL Flow Size in Bytes,%.3f\n", ssl_connection_size_bytes/total_ssl_flows);
    	printf("\tTotal SSL flows(443):                      %-13llu \n", (long long unsigned int)total_ssl_flows);
   	fprintf(f_conn, "Total SSL flows(443),%llu\n", (long long unsigned int)total_ssl_flows);
    	printf("\tTotal SSL Bytes:                           %-13llu \n", (long long unsigned int)ssl_connection_size_bytes);
   	fprintf(f_conn, "Total SSL Bytes,%llu\n", (long long unsigned int)ssl_connection_size_bytes);
   	printf("\tSSL Flows / Gbps(443):                     %-13.3f\n", (float)total_ssl_flows/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
   	fprintf(f_conn, "SSL Flows / Gbps(443),%.3f\n", (float)total_ssl_flows/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
//   	printf("\tTotal SSL Certs:                           %-13.3f\n",(float)ssl_cert_counter);
//   	fprintf(f_conn, "Total SSL Certs,%.3f\n",(float)ssl_cert_counter);
   	printf("\tTotal SSL Certs / Gbps:                    %-13.3f\n",(float)ssl_cert_counter/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
   	fprintf(f_conn, "Total SSL Certs / Gbps,%.3f\n",(float)ssl_cert_counter/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
//   	printf("\tTotal SSL Client Hello + SNI:              %-13.3f\n",(float)ssl_sni_counter);
//   	fprintf(f_conn, "Total SSL Client Hello + SNI,%.3f\n",(float)ssl_sni_counter);
   	printf("\tTotal SSL Client Hello + SNI / Gbps:       %-13.3f\n",(float)ssl_sni_counter/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
   	fprintf(f_conn, "Total SSL Client Hello + SNI,%.3f\n",(float)ssl_sni_counter/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
    }
    printf("\tTotal Flows / Gbps:                        %-13.3f\n\n\n", (float)total_flows/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));
    fprintf(f_conn, "Total Flows / Gbps,%.3f\n\n\n", (float)total_flows/(tot_eth_gbits_per_sec * (traffic_duration_all/1000000)));

fclose(f_general);
fclose(f_http);
fclose(f_sip);
fclose(f_sig);
fclose(f_sip_ip_list);
fclose(f_sip_couple_list);
fclose(f_sip_codecs);
fclose(f_per_sip_peer);
fclose(f_sip_content_type);
fclose(f_persecnewflow);
fclose(f_connection);
fclose(f_ips_list);
fclose(f_conn);
fclose(f_protocols);	

system("cat $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_codecs_stats.csv) |grep -e rtpmap -e T38|grep -e INVITE -e 200_OK|awk -F '/' '{print $1}'|sed 's/ /,/g'|awk -F ',' '{print $2\",\"$3\",\"$4}'|sort|uniq -c|sort -n >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_codecs_stats_sorted.csv)");
//system("cat $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_codecs_stats.csv) |grep -e rtpmap -e T38|grep -e INVITE -e 200_OK|awk -F '/' '{print $1}'|sed 's/ /,/g'|awk '{print $2\",\"$4}'|sort|uniq -c|sort -n|awk '{print $1\",\"$2}'|grep ,[0-Z] >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_codecs_stats_sorted.csv)");
system("cat $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_content_type_stats.csv) |grep application|awk -F ';' '{print $1}'|grep  -e INVITE -e 200_OK|sort |uniq -c|sort -n |sed 's/ //g'|sed 's/Content-Type//g'|sed 's/://g'>> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_content_type_sorted.csv)");
system("cat $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/request_response_per_sip_peer_stats_tmp.csv)|sort|uniq -c|sort -n|sed 's/ //g' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/request_response_per_sip_peer_stats.csv)");
system("cat $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/connection_stats_tmp.csv) >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/connection_stats.csv)");
system("cat $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/ip_list_tmp.csv) |sort |uniq -c|sort -n |awk '{print $1\",\"$2}' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/ip_list.csv)");
system("cat $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_ip_list_tmp.csv) |sort |uniq -c|sort -n |awk '{print $1\",\"$2\",\"$3}'|sed 's/,$//g' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_ip_list.csv)");
system("cat $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_couple_list_tmp.csv) |sort |uniq -c|sort -n |awk '{print $1\",\"$2\",\"$3\",\"$4}'|sed 's/,,//g' >> $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_couple_list.csv)");


system("rm -f $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/connection_stats_tmp.csv)");
system("rm -f $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_ip_list_tmp.csv)");
system("rm -f $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_couple_list_tmp.csv)");
//system("rm -f $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/ip_list_tmp.csv)");
//system("rm -f $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_codecs_stats.csv)");
system("rm -f $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/request_response_per_sip_peer_stats_tmp.csv)");
system("rm -f $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/sip_content_type_stats.csv)");
//system("rm -f $(echo /tmp/$(ls /tmp/|grep res|sort -n|tail -1)/ip_list.csv)");
system("echo");

//system("killall -9 /usr/local/bin/hslb_d &> /dev/null &");
  return 0;
}

/* ****************************************************** */

#ifdef WIN32
#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

struct timezone {
  int tz_minuteswest; /* minutes W of Greenwich */
  int tz_dsttime;     /* type of dst correction */
};

/* ***************************************************** */

#if 0
int gettimeofday(struct timeval *tv, void *notUsed) {
  tv->tv_sec = time(NULL);
  tv->tv_usec = 0;
  return(0);
}
#endif

/* ***************************************************** */

int gettimeofday(struct timeval *tv, struct timezone *tz) {
  FILETIME        ft;
  LARGE_INTEGER   li;
  __int64         t;
  static int      tzflag;

  if(tv) {
    GetSystemTimeAsFileTime(&ft);
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    t  = li.QuadPart;       /* In 100-nanosecond intervals */
    t -= EPOCHFILETIME;     /* Offset to the Epoch time */
    t /= 10;                /* In microseconds */
    tv->tv_sec  = (long)(t / 1000000);
    tv->tv_usec = (long)(t % 1000000);
  }

  if(tz) {
    if(!tzflag) {
      _tzset();
      tzflag++;
    }

    tz->tz_minuteswest = _timezone / 60;
    tz->tz_dsttime = _daylight;
  }

  return 0;
}
#endif /* WIN32 */
