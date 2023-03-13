#include <linux/version.h>
#include <linux/init.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/netfilter.h>
#include <linux/unistd.h>

#include <linux/delay.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/list.h>

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/random.h>
#include <linux/ipv6.h>
#include <linux/inet.h>

#include <net/switchdev.h>

#include "swacl_if.h"
#include "swacl_util.h"

int
swacl_if_str2argv(char *str, char *argv[], int argv_size)
{
	static char buff[1024];
	char *p = buff;
	int i = 0;

	strncpy(buff, str, 1024);
	while (p != NULL) {
		argv[i] = strsep(&p, " \t");
		if (strlen(argv[i]) > 0) {
			i++;
			if (i == argv_size - 1)
				break;
		}
	}
	argv[i] = 0;
	return i;
}

int
swacl_if_str2val(char *s)
{
	int val;
	if (s[0] == 'x') {
		sscanf(s + 1, "%x", &val);
	} else if (s[0] == '0' && s[1] == 'x') {
		sscanf(s + 2, "%x", &val);
	} else {
		sscanf(s, "%d", &val);
	}
	return val;
}
/* util_trim : removes leading and trailing spaces of a string */
char *
swacl_util_trim(char *s)
{
	int i;

	if (s) {
		i = strlen(s);
		while ((--i) > 0 && isspace(s[i]))
			s[i] = 0;
	}
	if (s) {
		while (isspace(*s))
			s++;
	}
	return s;
}
int
swacl_util_string_is_xdigit(char *str)
{
	char *s = str;
	int i;
	
	if (s[0] == '+' || s[0] == '-')
		s++;
	
	for (i=0; i<strlen(s); i++){
	
		if (s[i]<'0' || s[i]>'9'){
			if(!(s[i]>='a' && s[i]<='f') && !(s[i]>='A' && s[i]<='F'))
				return 0;
		}
	}
	return 1;
}

int
swacl_util_string_is_digit(char *str)
{
	char *s = str;
	int i;
	
	if (s[0] == '+' || s[0] == '-')
		s++;
	
	for (i=0; i<strlen(s); i++){
	
		if (s[i]<'0' || s[i]>'9')
			return 0;
	}
	return 1;
}

int
swacl_if_parse_OUI(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	char s1[2]={':','\0'};
	char * p_str=NULL;
	unsigned int pos=0,value=0;	
	char * buf = param_str;
	
	while ((p_str = strsep(&buf, s1)) != NULL) {
		
		p_str = swacl_util_trim(p_str);

		if(!swacl_util_string_is_xdigit(p_str)){
			dbprintk("OUI: isn't xdigit\n");
			memset(rule_entry->oui,0x0,OUI_LEN);
			rule_entry->filter_flags |= ~SWACL_IF_filter_OUI;
			return SWACL_IF_ERROR;
		}
		
		value = simple_strtoul(p_str,NULL,16);	
		rule_entry->oui[pos] = (unsigned char)value;
		pos++;			
	}
	if(pos != OUI_LEN-1){
		dbprintk("OUI: format error\n");
		memset(rule_entry->oui,0x0,OUI_LEN);
		rule_entry->filter_flags |= ~SWACL_IF_filter_OUI;
		return SWACL_IF_ERROR;
	}
	rule_entry->filter_flags |= SWACL_IF_filter_OUI;
	return SWACL_IF_SUCCESS;

}

int
swacl_if_parse_ethertype(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;

	param_str = swacl_util_trim(param_str);
	if(strncmp(param_str,"0x",2) != 0 && strncmp(param_str,"0X",2) != 0){
		dbprintk("ETHERTYPE: format error\n");	
		return SWACL_IF_ERROR;
	}
	if(!swacl_util_string_is_xdigit(param_str)){
		dbprintk("ETHERTYPE: isn't xdigit\n");	
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,16);
	rule_entry->ethertype = (unsigned short)value;	
	rule_entry->filter_flags |= SWACL_IF_filter_ETHERTYPE;

	return SWACL_IF_SUCCESS;
}

int 
swacl_if_parse_dmac(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	
	char s1[2]={':','\0'};
	char * p_str=NULL;
	unsigned int pos=0,value=0;	
	char * buf = param_str;
	
	while ((p_str = strsep(&buf, s1)) != NULL) {
		
		p_str = swacl_util_trim(p_str);

		if(!swacl_util_string_is_xdigit(p_str)){
			dbprintk("dmac: isn't xdigit\n");
			memset(rule_entry->dmac,0x0,VLAN_ETH_ALEN);
			rule_entry->filter_flags |= ~SWACL_IF_filter_DMAC;
			return SWACL_IF_ERROR;
		}
		
		value = simple_strtoul(p_str,NULL,16);	
		rule_entry->oui[pos] = (unsigned char)value;
		pos++;			
	}
	if(pos != VLAN_ETH_ALEN){
		dbprintk("dmac: format error\n");
		memset(rule_entry->dmac,0x0,VLAN_ETH_ALEN);
		rule_entry->filter_flags |= ~SWACL_IF_filter_DMAC;
		return SWACL_IF_ERROR;
	}
	rule_entry->filter_flags |= SWACL_IF_filter_DMAC;
	return SWACL_IF_SUCCESS;
}

int 
swacl_if_parse_dmac_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;

	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("dmac_prefix: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->ethertype = (unsigned short)value;	
	rule_entry->filter_flags |= SWACL_IF_filter_DMAC_PRE;

	return SWACL_IF_SUCCESS;
}

int 
swacl_if_parse_smac(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	
	char s1[2]={':','\0'};
	char * p_str=NULL;
	unsigned int pos=0,value=0;	
	char * buf = param_str;
	
	while ((p_str = strsep(&buf, s1)) != NULL) {
		
		p_str = swacl_util_trim(p_str);

		if(!swacl_util_string_is_xdigit(p_str)){
			dbprintk("smac: isn't xdigit\n");
			memset(rule_entry->dmac,0x0,VLAN_ETH_ALEN);
			rule_entry->filter_flags |= ~SWACL_IF_filter_SMAC;
			return SWACL_IF_ERROR;
		}
		
		value = simple_strtoul(p_str,NULL,16);	
		rule_entry->oui[pos] = (unsigned char)value;
		pos++;			
	}
	if(pos != VLAN_ETH_ALEN){
		dbprintk("smac: format error\n");
		memset(rule_entry->dmac,0x0,VLAN_ETH_ALEN);
		rule_entry->filter_flags |= ~SWACL_IF_filter_SMAC;
		return SWACL_IF_ERROR;
	}
	rule_entry->filter_flags |= SWACL_IF_filter_SMAC;
	return SWACL_IF_SUCCESS;
}

int 
swacl_if_parse_smac_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;

	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("smac_prefix: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->ethertype = (unsigned short)value;	
	rule_entry->filter_flags |= SWACL_IF_filter_SMAC_PRE;

	return SWACL_IF_SUCCESS;
}
int
swacl_if_parse_ifname(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	char * p_str=NULL;
	struct net_device *lowdev;
	unsigned int slen=0;	
	char * buf = param_str;

		
	p_str = swacl_util_trim(buf);
	
	if((slen = strlen(p_str)) > IFNAMSIZ){
		dbprintk("ifname: name too long error\n");			
		return SWACL_IF_ERROR;
	}
	if ((lowdev = dev_get_byname(p_str)) == NULL) {
		dbprintk("ifname: no netdev exist(%s)\n",p_str);			
		return SWACL_IF_ERROR;
	}
	dev_put(lowdev);
	strncpy(rule_entry->bind_ifname,buf,slen);
	rule_entry->filter_flags |= SWACL_IF_filter_IFNAME;
		
	
	return SWACL_IF_SUCCESS;

}
int
swacl_if_parse_v4proto(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;

	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("v4proto: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	if(value > 255){
		dbprintk("v4proto: error range\n");		
		return SWACL_IF_ERROR;
	}
		
	rule_entry->v4_protocol = (unsigned char)value;	
	rule_entry->filter_flags |= SWACL_IF_filter_V4_PROTO;

	return SWACL_IF_SUCCESS;

}

int
swacl_if_parse_v6_nxt_header(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	
	unsigned int value=0;
	
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("v6_nxt_header: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	if(value > 255){
		dbprintk("v6_nxt_header: error range\n");		
		return SWACL_IF_ERROR;
	}
		
	rule_entry->v6_next_header = (unsigned char)value;	
	rule_entry->filter_flags |= SWACL_IF_filter_V6_NXT_HEAD;

	return SWACL_IF_SUCCESS;
}

int 
swacl_if_parse_dip(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	char s1[2]={'.','\0'};
	char * p_str=NULL;
	unsigned int pos=0,value=0;	
	char * buf = param_str;

	if((p_str = strstr(buf, s1)) == NULL){
		
		dbprintk("dip: format error(%s)\n",buf);		
		return SWACL_IF_ERROR;		

	}else{
		rule_entry->dip = 0;	
		while ((p_str = strsep(&buf, s1)) != NULL) {
		
			p_str = swacl_util_trim(p_str);
			
			if(!swacl_util_string_is_digit(p_str)){
				dbprintk("dip: isn't digit\n");		
				return SWACL_IF_ERROR;
			}
		
			value = simple_strtoul(p_str,NULL,10);			
			rule_entry->dip |= value << (32 - (8*(pos+1)));
			pos++;			
		}

	}
	if(pos!=4){
		dbprintk("dip: format error\n");		
		return SWACL_IF_ERROR;
	}
	rule_entry->filter_flags |= SWACL_IF_filter_DIP;
	return SWACL_IF_SUCCESS;

}

int 
swacl_if_parse_dip_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
	
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("dip prefix: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->dip_prefix = (unsigned short)value;	
	rule_entry->filter_flags |= SWACL_IF_filter_DIP_PRE;

	return SWACL_IF_SUCCESS;

}
int 
swacl_if_parse_sip(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	char s1[2]={'.','\0'};
	char * p_str=NULL;
	unsigned int pos=0,value=0;	
	char * buf = param_str;

	if((p_str = strstr(buf, s1)) == NULL){
		
		dbprintk("sip: format error(%s)\n",buf);		
		return SWACL_IF_ERROR;		

	}else{
		rule_entry->sip = 0;	
		while ((p_str = strsep(&buf, s1)) != NULL) {
		
			p_str = swacl_util_trim(p_str);
			
			if(!swacl_util_string_is_digit(p_str)){
				dbprintk("sip: isn't digit\n");		
				return SWACL_IF_ERROR;
			}
		
			value = simple_strtoul(p_str,NULL,10);			
			rule_entry->sip |= value << (32 - (8*(pos+1)));
			pos++;			
		}

	}
	if(pos!=4){
		dbprintk("sip: format error\n");		
		return SWACL_IF_ERROR;
	}
	rule_entry->filter_flags |= SWACL_IF_filter_SIP;
	return SWACL_IF_SUCCESS;

}

int 
swacl_if_parse_sip_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
	
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("sip prefix: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->sip_prefix = (unsigned short)value;	
	rule_entry->filter_flags |= SWACL_IF_filter_SIP_PRE;

	return SWACL_IF_SUCCESS;	

}
int
swacl_if_parse_v6_dip(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	int ret;
	char s1[2]={':','\0'};
	char * p_str=NULL;
	unsigned int len=0;	
	char * buf = param_str;

	if((p_str = strstr(buf, s1)) == NULL){
		
		dbprintk("v6 dip: format error(%s)\n",buf);		
		return SWACL_IF_ERROR;		

	}else{
		p_str = swacl_util_trim(buf);
		len = strlen(p_str);	
		ret = in6_pton(buf,len,(void*)&rule_entry->v6dip,-1,NULL);
		if(ret != 1){
			dbprintk("v6 dip: in6_pton error(%s)\n",p_str);		
			return SWACL_IF_ERROR;	
		}
	}

	rule_entry->filter_flags |= SWACL_IF_filter_V6_DIP;

	return SWACL_IF_SUCCESS;	
}
int
swacl_if_parse_v6_dip_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("ip6 prefix: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->v6dip_prefix = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_filter_V6_DIP_PRE;

	return SWACL_IF_SUCCESS;	
}

int
swacl_if_parse_v6_sip(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	int ret;
	char s1[2]={':','\0'};
	char * p_str=NULL;
	unsigned int len=0;	
	char * buf = param_str;

	if((p_str = strstr(buf, s1)) == NULL){
		
		dbprintk("v6 sip: format error(%s)\n",buf);		
		return SWACL_IF_ERROR;		

	}else{
		p_str = swacl_util_trim(buf);
		len = strlen(p_str);	
		ret = in6_pton(buf,len,(void*)&rule_entry->v6sip,-1,NULL);
		if(ret != 1){
			dbprintk("v6 sip: in6_pton error(%s)\n",p_str);		
			return SWACL_IF_ERROR;	
		}
	}

	rule_entry->filter_flags |= SWACL_IF_filter_V6_SIP;

	return SWACL_IF_SUCCESS;	
}
int
swacl_if_parse_v6_sip_prefix(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("v6_sip prefix: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->v6sip_prefix = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_filter_V6_SIP_PRE;

	return SWACL_IF_SUCCESS;	
}

int
swacl_if_parse_dport(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("dport: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->dport_start = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_filter_DPORT;

	return SWACL_IF_SUCCESS;	

}

int
swacl_if_parse_dport_end(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("dport_end: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->dport_end = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_filter_DPORT_END;

	return SWACL_IF_SUCCESS;	

}

int
swacl_if_parse_sport(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("sport: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->sport_start = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_filter_SPORT;

	return SWACL_IF_SUCCESS;	

}

int
swacl_if_parse_sport_end(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("sport_end: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->sport_end = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_filter_SPORT_END;

	return SWACL_IF_SUCCESS;	

}

int 
swacl_if_parse_filter_vlan(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("sport_end: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->vlantag_id = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_filter_VLAN;

	return SWACL_IF_SUCCESS;	
}

int 
swacl_if_parse_filter_vlan_pbit(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("sport_end: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->vlan_tag_pbit = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_filter_VLAN_PRI;

	return SWACL_IF_SUCCESS;	
}
int
swacl_if_parse_act_vlan(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("sport_end: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->vlan_mark = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_ACTION_VLANTAG_CHG;

	return SWACL_IF_SUCCESS;		

}
int
swacl_if_parse_act_pbit(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("sport_end: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->pbit_mark = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_ACTION_PBIT_CHG;

	return SWACL_IF_SUCCESS;		

}
int
swacl_if_parse_rule_priority(char * param_str,struct swacl_if_rule_entry * rule_entry)
{
	unsigned int value=0;
		
	param_str = swacl_util_trim(param_str);
	if(!swacl_util_string_is_digit(param_str)){
		dbprintk("rule pri: isn't digit\n");		
		return SWACL_IF_ERROR;
	}
		
	value = simple_strtoul(param_str,NULL,10);
	rule_entry->priority = (unsigned short)value; 
	rule_entry->filter_flags |= SWACL_IF_ACTION_RULE_PRIORITY;

	return SWACL_IF_SUCCESS;		
}


