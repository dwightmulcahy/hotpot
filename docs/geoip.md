# GeoLite ASN and GeoIP enrichment

Hotpot's centralized dashboard can enrich public attacker addresses from local MaxMind MMDB files. The dashboard never sends attacker IPs to an external GeoIP API.

## QNAP layout

The QNAP examples use:

```text
/share/Data/config/cloudflared/
├── dashboard.env
├── geoipupdate.env
└── geoip/
    ├── GeoLite2-ASN.mmdb
    └── GeoLite2-City.mmdb
```

Create the database directory:

```sh
mkdir -p /share/Data/config/cloudflared/geoip
chmod 775 /share/Data/config/cloudflared/geoip
```

Copy `geoipupdate.env.example` to `/share/Data/config/cloudflared/geoipupdate.env`, enter the MaxMind account ID and license key, then protect the file:

```sh
chmod 600 /share/Data/config/cloudflared/geoipupdate.env
```

The Compose examples run the official `ghcr.io/maxmind/geoipupdate` image. It downloads the configured databases when the container starts and checks again every `GEOIPUPDATE_FREQUENCY` hours. The supplied example checks every 24 hours and downloads `GeoLite2-ASN` and `GeoLite2-City`.

The updater writes to `/share/Data/config/cloudflared/geoip`, while the Hotpot dashboard mounts the same directory read-only at `/geoip`.

Configure the dashboard with:

```dotenv
HOTPOT_GEOIP_ASN_DB=/geoip/GeoLite2-ASN.mmdb
HOTPOT_GEOIP_CITY_DB=/geoip/GeoLite2-City.mmdb
HOTPOT_GEOIP_COUNTRY_DB=
```

## Automatic reload

The dashboard checks the MMDB file signatures on its normal refresh interval. When `geoipupdate` replaces a database, the dashboard opens the new database, clears cached IP lookups, and begins using the updated data without a dashboard restart.

`/api/overview` reports GeoIP status including loaded databases, reload count, last reload time, file size, and file modification signature.

## Troubleshooting

Check the updater logs:

```sh
docker logs geoipupdate --tail 100
```

Confirm the files exist:

```sh
ls -lh /share/Data/config/cloudflared/geoip
```

Temporarily enable verbose updater logs by setting:

```dotenv
GEOIPUPDATE_VERBOSE=1
```

Then recreate the `geoipupdate` container so the changed environment is loaded.
