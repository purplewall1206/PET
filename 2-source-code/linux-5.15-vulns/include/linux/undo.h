#ifndef _LINUX_UNDO_H
#define _LINUX_UNDO_H

extern unsigned long ooo[12] = {0};

extern unsigned long bowknot_pairmask = 0;
extern unsigned long bowknot_flag = 0;

#define CGOTO0 if(ooo[0] != 0 && unlikely(bowknot_flag)) goto bowknot_label;
#define CGOTO1 if(ooo[1] != 0 && unlikely(bowknot_flag)) goto bowknot_label;
#define CGOTO2 if(ooo[2] != 0 && unlikely(bowknot_flag)) goto bowknot_label;
#define CGOTO3 if(ooo[3] != 0 && unlikely(bowknot_flag)) goto bowknot_label;
#define CGOTO4 if(ooo[4] != 0 && unlikely(bowknot_flag)) goto bowknot_label;
#define CGOTO5 if(ooo[5] != 0 && unlikely(bowknot_flag)) goto bowknot_label;
#define CGOTO6 if(ooo[6] != 0 && unlikely(bowknot_flag)) goto bowknot_label;
#define CGOTO7 if(ooo[7] != 0 && unlikely(bowknot_flag)) goto bowknot_label;
#define CGOTO8 if(ooo[8] != 0 && unlikely(bowknot_flag)) goto bowknot_label;
#define CGOTO9 if(ooo[9] != 0 && unlikely(bowknot_flag)) goto bowknot_label;


// #define setbit() 	bowknot_pairmask=bowknot_pairmask | (1 << 4)
// #define unsetbit() bowknot_pairmask=bowknot_pairmask&(0xffffffffffffffff ^ (1 << 4))

#endif