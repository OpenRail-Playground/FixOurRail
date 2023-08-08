# Fix Our Rail

Check OpenStreetMap data for strange data about railway tracks and publish to [osmose](https://osmose.openstreetmap.fr/).

## How to use

You need npm and [osmium tool](https://osmcode.org/osmium-tool/) (there might be a packet existing in your distribution).

### Install dependencies

`sudo apt install osmium-tool # on debian/ubuntu`

`npm install`

### Get the data to test

Find the country you want to analyse on https://download.geofabrik.de/

### Launch the analysis

`sh process-pbf.sh some_country.osm.pbf > result.xml`

The result.xml file can be uploaded to an osmose instance

## Context of the project

The [osrd](https://osrd.fr/en/) projects can use OpenStreetMap data to simulate train routes.

This project was a response to a challenge suggested by SNCF Réseau during the [Dreiländerhack](https://bcc.oebb.at/de/das-leisten-wir/innovationen/dreilaenderhack).

### Contributors

* [Julius Tens](https://github.com/juliuste)
* [Daniel Rohr](https://github.com/at-dro)
* [Max Mehl](https://github.com/mxmehl)
* Jennifer Prasiswa
* [Tristram Gräbener](https://github.com/tristramg)

### License

The content of this repository is licensed under the [Apache 2.0 license](LICENSE).
