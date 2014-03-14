CCA2 Secure Scheme Implementation Content
==

This work compares current state-of-the-art CCA2-secure schemes on both, a theoretical and practical, level. To realize that, we exemplarily choose nine schemes that achieve CCA2- security by using decisional hardness assumptions and three, which attain this security goal with the help of computational assumptions. With those schemes we cover the most important and recent approaches in order to make a cryptographic algorithm CCA2-secure.

This project covers the theoretical and practical comparison of those schemes, as far as it is possible. This means, that some schemes are sheer incomparable due to different hardness assumptions or security goals. We concentrate on a runtime analysis as well as on an evaluation of the security aims achieved. We also suggest changes for practical implementations and thus, improve the efficiency. On top of that, we implement ten schemes with the help of the cryptographic framework Charm ([Official Website](http://http://www.charm-crypto.com/Main.html)), which already provides useful mathematical and cryptographic functionalities.

Content of this Repository
--

This repository only covers a small amount of the work and some of the implementations as a proof of concept. See [here](TBD) for the whole work.

1. Boney-Canetti-Halevi-Katz
2. Cramer-Shoup based on DCR
3. Cramer-Shoup based on DDH
4. Haralambiev-Jager-Kiltz-Shoup
5. Hybrid Cramer-Shoup
6. Hofheinz-Kiltz-Shoup
7. Kurosawa-Desmedt 

