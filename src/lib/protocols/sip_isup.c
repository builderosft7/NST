/*
 * sip.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */


#include "ndpi_api.h"


#ifdef NDPI_PROTOCOL_SIP_ISUP
static void ndpi_int_sip_isup_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow,
					u_int8_t due_to_correlation)
{

  ndpi_int_add_connection(ndpi_struct, flow,
			  NDPI_PROTOCOL_SIP_ISUP,
			  due_to_correlation ? NDPI_CORRELATED_PROTOCOL : NDPI_REAL_PROTOCOL);
}

	
#if !defined(WIN32)
static inline
#else
__forceinline static
#endif
void ndpi_search_sip_isup_handshake(struct ndpi_detection_module_struct
			       *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;
  const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;


#ifndef NDPI_PROTOCOL_YAHOO
  if (payload_len >= 14 && packet_payload[payload_len - 2] == 0x0d && packet_payload[payload_len - 1] == 0x0a)
#endif
#ifdef NDPI_PROTOCOL_YAHOO
    if (payload_len >= 14)
#endif
      {




	if ((memcmp(packet_payload, "INVITE ", 7) == 0 || memcmp(packet_payload, "invite ", 7) == 0)
	    && (memcmp(&packet_payload[7], "SIP:", 4) == 0 || memcmp(&packet_payload[7], "sip:", 4) == 0)) {
	  	  NDPI_LOG(NDPI_PROTOCOL_SIP, ndpi_struct, NDPI_LOG_DEBUG, "found sip INVITE.\n");
		  int i;
		  for(i=50; i <1300; i++) {
                      if(memcmp(&packet_payload[i], "ion/isup", 8) == 0) {
	  		    ndpi_int_sip_isup_add_connection(ndpi_struct, flow, 0);
  //                          printf("found isup \n");
  //                          break;
			    return;
                     }
		  }

	  return;
	}

        if (memcmp(packet_payload, "SIP/2.0 ", 8) == 0 || memcmp(packet_payload, "sip/2.0 ", 8) == 0) {
	  NDPI_LOG(NDPI_PROTOCOL_SIP, ndpi_struct, NDPI_LOG_DEBUG, "found sip SIP/2.0 *.\n");
		  int i;
		  for(i=50; i <1300; i++) {
                      if(memcmp(&packet_payload[i], "ion/isup", 8) == 0) {
	  		    ndpi_int_sip_isup_add_connection(ndpi_struct, flow, 0);
                            printf("found isup \n");
  //                          break;
                              return;
                     }
		  }

	  return;
	}




      }

  /* add bitmask for tcp only, some stupid udp programs
   * send a very few (< 10 ) packets before invite (mostly a 0x0a0x0d, but just search the first 3 payload_packets here */
  if (packet->udp != NULL && flow->packet_counter < 20) {
    NDPI_LOG(NDPI_PROTOCOL_SIP_ISUP, ndpi_struct, NDPI_LOG_DEBUG, "need next packet.\n");
    return;
  }


}


void ndpi_search_sip_isup(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  //  struct ndpi_flow_struct   *flow = ndpi_struct->flow;
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  NDPI_LOG(NDPI_PROTOCOL_SIP_ISUP, ndpi_struct, NDPI_LOG_DEBUG, "sip detection...\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_SIP_ISUP) {
    if (packet->tcp_retransmission == 0) {
      ndpi_search_sip_isup_handshake(ndpi_struct, flow);
    }
  }
}
#endif
