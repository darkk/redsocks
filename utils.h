#ifndef UTILS_H_SAT_FEB__2_02_24_05_2008
#define UTILS_H_SAT_FEB__2_02_24_05_2008

#define SIZEOF_ARRAY(arr)        (sizeof(arr) / sizeof(arr[0]))
#define FOREACH(ptr, array)      for (ptr = array; ptr < array + SIZEOF_ARRAY(array); ptr++)
#define FOREACH_REV(ptr, array)  for (ptr = array + SIZEOF_ARRAY(array) - 1; ptr >= array; ptr--)

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* UTILS_H_SAT_FEB__2_02_24_05_2008 */
