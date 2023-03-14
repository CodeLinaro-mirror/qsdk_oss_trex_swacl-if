#ifndef __SWACL_UTIL_H__
#define __SWACL_UTIL_H__
int
swacl_if_str2argv(char *str, char *argv[], int argv_size);
int
swacl_if_str2val(char *s);
int
swacl_util_string_is_xdigit(char *str);
int
swacl_util_string_is_digit(char *str);
int
swacl_if_parse_OUI(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_ethertype(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_dmac(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_dmac_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_smac(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_smac_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_ifname(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_v4proto(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_v6_nxt_header(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_dip(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_dip_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_sip(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_sip_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_v6_dip(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_v6_dip_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_v6_sip(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_v6_sip_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_dport(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_dport_end(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_sport(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_sport_end(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_filter_vlan(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_parse_filter_vlan_pbit(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_act_vlan(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_act_pbit(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_parse_rule_priority(char * param_str,struct swacl_if_rule_entry * rule_entry);


////////////////////////////////
int
swacl_if_OUI_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);

int
swacl_if_ethertype_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_dmac_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_dmac_prefix_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_smac_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_smac_prefix_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_ifname_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_v4proto_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_v6_nxt_header_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_dip_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_dip_prefix_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_sip_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int 
swacl_if_sip_prefix_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_v6_dip_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_v6_dip_prefix_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_v6_sip_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_v6_sip_prefix_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_dport_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_dport_end_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_sport_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_sport_end_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_vlan_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_vlan_pbit_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_act_vlan_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_act_pbit_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);
int
swacl_if_rule_priority_to_str(char * param_str,struct swacl_if_rule_entry * rule_entry);

#endif
