#include "config.h"

#include <epan/packet.h>

static int proto_xdp = -1;
static gint ett_xdp = -1;
static int hf_xdp_pkt_size = -1;
static int hf_xdp_delivery_flag = -1;
static int hf_xdp_number_msgs = -1;
static int hf_xdp_seq_num = -1;
static int hf_xdp_send_time = -1;
static int hf_xdp_send_time_ns = -1;

void proto_register_xdp(void)
{

	proto_xdp = proto_register_protocol(
			"Exchange Data Publisher",
			"XDP",
			"xdp"
		);

	static hf_register_info hf[] = {
        { &hf_xdp_pkt_size,
            { "PktSize", "xdp.hdr.pktsize",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xdp_delivery_flag,
            { "DeliveryFlag", "xdp.hdr.deliveryflag",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xdp_number_msgs,
            { "NumberMsgs", "xdp.hdr.numbermsgs",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xdp_seq_num,
            { "SeqNum", "xdp.hdr.seqnum",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xdp_send_time,
            { "SendTime", "xdp.hdr.sendtime",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xdp_send_time_ns,
            { "SendTimeNS", "xdp.hdr.sendtimens",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = { &ett_xdp };

    proto_register_field_array(proto_xdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void dissect_xdp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
    col_set_str( pinfo->cinfo, COL_PROTOCOL, "XDP" );
    col_clear( pinfo->cinfo, COL_INFO );

    if(tree)
    {
    	proto_item *ti = NULL;
    	proto_tree *xdp_tree = NULL;

    	ti = proto_tree_add_item(tree, proto_xdp, tvb, 0, -1, ENC_NA);
    	xdp_tree = proto_item_add_subtree(ti, ett_xdp);
    	proto_tree_add_item(xdp_tree, hf_xdp_pkt_size, tvb, 0, 2, ENC_LITTLE_ENDIAN);
    	proto_tree_add_item(xdp_tree, hf_xdp_delivery_flag, tvb, 2, 1, ENC_LITTLE_ENDIAN);
    	proto_tree_add_item(xdp_tree, hf_xdp_number_msgs, tvb, 3, 1, ENC_LITTLE_ENDIAN);
    	proto_tree_add_item(xdp_tree, hf_xdp_seq_num, tvb, 4, 4, ENC_LITTLE_ENDIAN);
    	proto_tree_add_item(xdp_tree, hf_xdp_send_time, tvb, 8, 4, ENC_LITTLE_ENDIAN);
    	proto_tree_add_item(xdp_tree, hf_xdp_send_time_ns, tvb, 12, 4, ENC_LITTLE_ENDIAN);
    }
}

void proto_reg_handoff_xdp(void)
{
	static dissector_handle_t hXDP;

	hXDP = create_dissector_handle( dissect_xdp, proto_xdp );
	dissector_add_uint( "udp.port", 36210, hXDP );
	dissector_add_uint( "udp.port", 46627, hXDP );
}

