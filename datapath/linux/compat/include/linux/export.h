#ifndef __LINUX_EXPORT_WRAPPER_H
#define __LINUX_EXPORT_WRAPPER_H

#ifndef HAVE_EXPORT_SYMBOL
#include_next <linux/module.h>
#else
#include_next <linux/export.h>
#endif

#endif /* __LINUX_EXPORT_WRAPPER_H */
