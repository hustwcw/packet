#ifndef __DOM_H__
#define __DOM_H__

#include "../iks/common.h"
#include "../iks/iksemel.h"

/*****  dom parser  *****/
enum iksfileerror {
	IKS_FILE_NOFILE = 4,
	IKS_FILE_NOACCESS,
	IKS_FILE_RWERR
};

iksparser *iks_dom_new (iks **iksptr);
void iks_set_size_hint (iksparser *prs, size_t approx_size);
iks *iks_tree (const char *xml_str, size_t len, int *err);
int iks_load (const char *fname, iks **xptr);
int iks_save (const char *fname, iks *x);

#endif /*__DOM_H__*/	
