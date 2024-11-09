## Gfury

Gfury, C dilinde yazılmış bir programdır. Amacı Mac cihazlarda TTL değiştirdikten sonra girilemeyen uygulamalar veya oyunlarda TTL'i manipüle etmektir. Ayrıca oyunlarda gönderilen TCP ve UDP paketlerini öncelikli olarak işaretler ve bu sayede pingin de düşmesini sağlar.

## Gereksinimler
- Gcc veya clang c derleyecilerinden birisi

## Kullanım

1. Bu repoyu klonlayın veya indirin.
2. `brew install libpcap` komutu ile gereksinimleri kurun.
2. `gcc gfury.c -o gfury -lpthread -lpcap` komutunu kullanarak derleyin.
3. `chmod +x gfury` komutu ile gerekli izinleir verin.
4. `sudo ./gfury` komutunu yazdıktan sonra hedef uygulamayı terminale sürükleyin ve çalıştırın.
