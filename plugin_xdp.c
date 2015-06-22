#include "config.h"

#include <epan/packet.h>

static int proto_xdp = -1;
static int hf_xdp_pdu_type = -1;
static gint ett_xdp = -1;

void proto_register_xdp(void)
{

	proto_xdp = proto_register_protocol(
			"Exchange Data Publisher",
			"XDP",
			"xdp"
		);
}

static void dissect_xdp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
    col_set_str( pinfo->cinfo, COL_PROTOCOL, "XDP" );
    //col_clear( pinfo->cinfo, COL_INFO );

    gint offset = 0;

    if(tree)
    {
    	proto_item *ti = NULL;
    	//proto_tree *xdp_tree = NULL;

    	ti = proto_tree_add_item(tree, proto_xdp, tvb, 0, -1, ENC_NA);
    	//xdp_tree = proto_item_add_subtree(ti, ett_xdp);
    	//proto_tree_add_item(xdp_tree, hf_xdp_pdu_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    	//xdp_tree = proto_tree_add_item(tree, proto_xdp, tvb, 0, -1, ENC_NA);
    	//ti = proto_item_add_subtree(xdp_tree, ett_xdp);

    	offset += 2;

    }
}

void proto_reg_handoff_xdp(void)
{
	static dissector_handle_t hXDP;

	hXDP = create_dissector_handle( dissect_xdp, proto_xdp );
	dissector_add_uint( "udp.port", 36210, hXDP );
	dissector_add_uint( "udp.port", 46627, hXDP );
}

