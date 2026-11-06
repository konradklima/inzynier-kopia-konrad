# alert-scanner

Projekt inżynierski, UKEN Kraków, Cyberbezpieczeństwo.
Autorzy: Rudolf Baranko, Dawid Hamryszczak, Konrad Klima.

Program skanuje stronę internetową skanerem OWASP ZAP, odrzuca mało istotne alerty, układa resztę
od najpilniejszych i opisuje je prostym językiem. Ma pomóc komuś, kto prowadzi stronę, ale nie
zajmuje się bezpieczeństwem.

Na razie działa z linii poleceń. Później dojdzie pulpit, animowane wyjaśnienia zagrożeń i model ML
do oceny ryzyka.

## Instalacja

Potrzebny jest Python 3.11 lub nowszy. Docker Desktop jest potrzebny tylko do skanowania na żywo.

```sh
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

Na macOS i Linuksie środowisko włącza się przez `source .venv/bin/activate`.

## Uruchomienie

Analiza gotowego raportu ZAP (bez Dockera):

```sh
alert-scanner --report reports/zap-full-juiceshop.json --target http://host.docker.internal:3000
```

Skan na żywo. Celem testowym jest OWASP Juice Shop, czyli aplikacja celowo pełna dziur:

```sh
docker compose up -d
alert-scanner --scan http://host.docker.internal:3000
```

Adres `host.docker.internal` pozwala kontenerowi ze skanerem dotrzeć do Juice Shopa działającego
na tym samym komputerze.

Dodatkowe opcje:

- `--mode` wybiera tryb skanu (opis niżej),
- `--ajax` włącza pająka z przeglądarką, potrzebnego przy aplikacjach takich jak Juice Shop,
- `--compare juice-shop` porównuje wynik ze znanymi podatnościami Juice Shopa,
- `--show-filtered` pokazuje też odrzucone alerty,
- `--html plik.html` zapisuje raport HTML,
- `--history` pokazuje zapisane skany, a `--load ID` otwiera jeden z nich.

## Tryby skanu

- `baseline` to skan pasywny. ZAP tylko ogląda odpowiedzi serwera. Trwa około 2 minut.
- `full` to skan aktywny ze wszystkimi regułami ZAP-a. Na Juice Shopie trwa około 25 minut.
- `focused` to skan aktywny tylko z regułami z naszego katalogu zagrożeń.

Skan aktywny to prawdziwe ataki, więc wolno go uruchamiać tylko na własnych stronach albo za
pisemną zgodą właściciela.

## Testy

```sh
pytest
```

Testy sprawdzają najważniejsze funkcje i nie potrzebują Dockera.

## Struktura

Kod jest w `src/alert_scanner/`:

- `cli.py` - uruchamianie programu i wydruk w terminalu
- `scanner.py` - uruchomienie ZAP-a w Dockerze
- `zap_parser.py` - odczyt raportu ZAP-a, jedyne miejsce znające jego format
- `domain.py` - model danych
- `risk_rules.py` - ocena ryzyka i kolejność zagrożeń
- `catalog.py` - kategorie zagrożeń i ich nazwy prostym językiem
- `known_vulnerabilities.py` - porównanie wyniku ze znanymi podatnościami Juice Shopa
- `storage.py` - historia skanów w SQLite
- `report_html.py` - tymczasowy raport HTML

W `reports/` są dwa gotowe raporty ZAP-a ze skanu Juice Shopa: pasywny i aktywny.
