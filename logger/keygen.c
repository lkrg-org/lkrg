#include <stdio.h>

#include "hydrogen/hydrogen.c"

int main(void)
{
	hydro_kx_keypair server_static_kp;
	char hex[(hydro_kx_PUBLICKEYBYTES | hydro_kx_SECRETKEYBYTES) * 2 + 1];

	hydro_kx_keygen(&server_static_kp);

	printf("LKRG_LOGGER_PK=%s\n", hydro_bin2hex(hex, sizeof(hex), server_static_kp.pk, hydro_kx_PUBLICKEYBYTES));
	printf("LKRG_LOGGER_SK=%s\n", hydro_bin2hex(hex, sizeof(hex), server_static_kp.sk, hydro_kx_SECRETKEYBYTES));

	return 0;
}
