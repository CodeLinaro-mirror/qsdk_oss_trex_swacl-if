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



#endif
