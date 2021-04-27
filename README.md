# Freebox-Revolution-Monitoring
Freebox Revolution monitoring using telegraf/influxdb/grafana dockers on Synology NAS
Using API V8 for maximum compatibility with Freebox OS boxes
** Si vous venez d'une version précédente, il est grandement conseillé de créer une nouvelle base influxdb
** Par ailleurs, le polling telegraf est toujurs laissé à 10sec, mais le timeout est positionné à 8sec. car 5sec. provoque de temps en temps des timeout de requetes.

Vous trouverez le script Python (freebox_061.py), des screenshot des évolutions avec les requêtes grafana correspondantes.
Enfin, un fichier API V8.pdf donnant l'ensemble des paramètres accessibles en fonction des arguments passés au script.
