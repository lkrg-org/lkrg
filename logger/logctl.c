/*
 * Process an LKRG logger output file.  This program currently derives each
 * event's ISO timestamp from several recorded relative timestamps.
 *
 * Written in 2022 by Solar Designer
 * Copyright (c) 2022 Binarly
 */

#include <time.h>
#include <stdio.h>

static const char *format_time(char *s, size_t max, unsigned long long t)
{
	time_t tu = t / 1000000;
	struct tm *tm = gmtime(&tu);
	if (strftime(s, max, "%Y-%m-%dT%H:%M:%SZ", tm))
		return s;
	return "";
}

static int process_log(const char *pathname)
{
	int retval = 0;

	FILE *f = fopen(pathname, "r");
	if (!f) {
		perror("fopen");
		return 1;
	}

	char buf[0x2100];
	while (fgets(buf, sizeof(buf), f)) {
		unsigned long long tr, ts, tsu, seq, teu;
		unsigned int sev;
		char type;
		int msgofs = 0;
		int n = sscanf(buf, "%llu,%llu,%llu,%u,%llu,%llu,%c;%n", &tr, &ts, &tsu, &sev, &seq, &teu, &type, &msgofs);
		if (n < 7 || !msgofs || (type != '-' && type != 'c')) {
			if (!(retval & 2)) {
				fputs("Warning: Skipping misformatted line(s)\n", stderr);
				retval |= 2;
			}
			continue;
		}
		const char *msg = buf + msgofs;

		unsigned long long te = ts;
		if (tsu > teu) {
/*
 * Infer more accurate event time by subtracting the delay between send uptime
 * and event uptime from the send time.
 */
			te -= tsu - teu;
		} else if (teu - tsu >= 500000 && !(retval & 4)) {
			fputs("Warning: Major system uptime clock drift between CPUs\n", stderr);
			retval |= 4;
		}

		char ste[21];
		printf("%s %c %s", format_time(ste, sizeof(ste), te), type, msg);
	}

	if (ferror(f)) {
		perror("fgets");
		retval |= 1;
	}

	fclose(f);

	return retval;
}

int main(int argc, const char * const *argv)
{
	if (argc != 2) {
		fputs("Usage: lkrg-logctl PATHNAME\n", stderr);
		return 1;
	}

	return process_log(argv[1]);
}
