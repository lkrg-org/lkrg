/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - (Un)Immunization module
 *
 * Notes:
 *  - Gives kernel a dose of vaccine
 *
 * Timeline:
 *  - Created: 20.I.2022
 *
 * Author:
 *  - Ilya 'milabs' Matveychikov (https://github.com/milabs)
 *
 */

#ifndef P_LKRG_IMMUNITY_MODULE_H
#define P_LKRG_IMMUNITY_MODULE_H

void p_vaccinate(void);
void p_devaccinate(void);

#endif
