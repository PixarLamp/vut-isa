Zuzana Hrkľová, xhrklo00
14.11.2022

Program na tunelovanie dát cez DNS dotazy. Obsahuje implementáciu klienta posielajúceho dáta zakódované v DNS paketoch pomocou UDP protokolu a implementáciu servera rozšifrujúceho prijaté správy, ktoré následne uloží do súboru zadaného na vstupe.

Návod na spustenie

preklad pomocou Makefile pre server make reciever, klienta make sender alebo všetko naraz make/make all

spustenie klienta: 
./dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]

-u : slúži na vynútenie vzdialeného DNS serveru, ak nie je špecifikovaná program využije DNS server nastavený v systéme
BASE_HOST : slúži k nastaveniu bázovej domény
DST_FILEPATH : cesta pod ktorou sa data uložia na servey
SRC_FILEPATH : cesta k súboru, ktorý bude odoslaný, ak nieje špecifikovaná použije sa STDIN

spustenie serveru:
./dns_receiver {BASE_HOST} {DST_DIRPATH}

BASE_HOST : slúži k nastaveniu bázovej domény na prijímanie dát
DST_DIRPATH : cesta pod ktorou sa budú všetky prichádzajúce dáta ukladať

Obmedzenia

Server je schopný komunikovať len s jedným klientom zároveň.
Klient neprijíma odpoveď od servera a teda sa môže stať. že sa niektoré data pri odosielaní stratia. Klient je niekedy rýchlejší ako server a pošle novú správu skôr ako server stihol spracovať starú.

Odovzdané súbory:
    Makefile
    README.md
    manual.pdf
    sender/dns_sender.c
        /dns_sender.h
        /dns_sender_events.c
        /dns_sender_events.h
    receiver/dns_receiver.c
            /dns_receiver.h
            /dns_receiver_events.c
            /dns_receiver_events.h