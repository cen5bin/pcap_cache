#pragma once




#ifdef __cplusplus
extern "C" {
#endif

void init_ac_automation(char *keys[], int size);
int query_string(char *s);
void destroy_ac_automation();


#ifdef __cplusplus
}
#endif
