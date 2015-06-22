#include "config.h"

#include <epan/packet.h>

static int proto_xdp = -1;

void proto_register_xdp(void)
{
	proto_xdp = proto_register_protocol(
			"XDP protocol",
			"XDP",
			"xdp"
		);
}

static void dissect_xdp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
    col_set_str( pinfo->cinfo, COL_PROTOCOL, "XDP" );
    col_clear( pinfo->cinfo, COL_INFO );
}

void proto_reg_handoff_xdp(void)
{
	static dissector_handle_t hXDP;

	hXDP = create_dissector_handle( dissect_xdp, proto_xdp );
	dissector_add_uint( "udp.port", 36210, hXDP );
	dissector_add_uint( "udp.port", 46627, hXDP );
}

