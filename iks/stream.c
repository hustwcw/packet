/* iksemel (XML parser for Jabber)
** Copyright (C) 2000-2007 Gurer Ozen <madcat@e-kolay.net>
** This code is free software; you can redistribute it and/or
** modify it under the terms of GNU Lesser General Public License.
*/

#include "common.h"
#include "iksemel.h"


struct stream_data {
	iksparser *prs;
	ikstack *s;
	void *user_data;
	iksStreamHook *streamHook;
	iks *current;
};


static void
insert_attribs (iks *x, char **atts)
{
	if (atts) {
		int i = 0;
		while (atts[i]) {
			iks_insert_attrib (x, atts[i], atts[i+1]);
			i += 2;
		}
	}
}


static int
tagHook (struct stream_data *data, char *name, char **atts, int type)
{
	iks *x;
	int err;

	switch (type) {
		case IKS_OPEN:
		case IKS_SINGLE:
			if (data->current) {
				x = iks_insert (data->current, name);
				insert_attribs (x, atts);
			} else {
				x = iks_new (name);
				insert_attribs (x, atts);
				if (iks_strcmp (name, "stream:stream") == 0) {
					err = data->streamHook (data->user_data, x);
					if (err != IKS_OK) return err;
					break;
				}
			}
			data->current = x;
			if (IKS_OPEN == type) break;
		case IKS_CLOSE:
			x = data->current;
			if (NULL == x) {
				err = data->streamHook (data->user_data, NULL);
				if (err != IKS_OK) return err;
				break;
			}
			if (NULL == iks_parent (x)) {
				data->current = NULL;
				err = data->streamHook (data->user_data, x);
				if (err != IKS_OK) return err;
				break;
			}
			data->current = iks_parent (x);
	}
	return IKS_OK;
}

static int
cdataHook (struct stream_data *data, char *cdata, size_t len)
{
	if (data->current) iks_insert_cdata (data->current, cdata, len);
	return IKS_OK;
}

static void
deleteHook (struct stream_data *data)
{
	if (data->current) iks_delete (data->current);
	data->current = NULL;
}

iksparser *
iks_stream_new (void *user_data, iksStreamHook *streamHook)
{
	ikstack *s;
	struct stream_data *data;

	s = iks_stack_new (DEFAULT_STREAM_CHUNK_SIZE, 0);
	if (NULL == s) return NULL;
	data = iks_stack_alloc (s, sizeof (struct stream_data));
	memset (data, 0, sizeof (struct stream_data));
	data->s = s;
	data->prs = iks_sax_extend (s, data, (iksTagHook *)tagHook, (iksCDataHook *)cdataHook, (iksDeleteHook *)deleteHook);
	data->user_data = user_data;
	data->streamHook = streamHook;
	return data->prs;
}


int iks_parse_stream(iksparser *prs, char *buf,int len)
{
	int ret;
    ret = iks_parse (prs, buf, len, 0);
	return ret;
}
