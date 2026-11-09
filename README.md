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
- `--scope` wybiera zakres: `site` (wszystkie podstrony) albo `page` (tylko główna strona),
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

## Przykłady skanowania

Szybki skan pasywny własnej strony wraz z podstronami, bez ryzyka dla serwera:

```sh
alert-scanner --scan https://twoja-strona.pl --scope site --mode baseline --html reports/strona.html
```

- `alert-scanner` - uruchamia program,
- `--scan https://twoja-strona.pl` - skanuje podaną stronę na żywo, w jej miejsce wpisz własny adres,
- `--scope site` - sprawdza stronę główną i szybko odkrywa wszystkie podstrony (`--scope page` sprawdza tylko stronę główną),
- `--mode baseline` - skan pasywny, ZAP tylko ogląda odpowiedzi serwera,
- `--html reports/strona.html` - zapisuje raport HTML z podziałem na podstrony w podanym pliku.

Skan aktywny z ograniczeniem czasu, żeby nie trwał dłużej niż pół godziny:

```sh
alert-scanner --scan https://twoja-strona.pl --scope site --mode full --max-minutes 30
```

- `--mode full` - skan aktywny ze wszystkimi regułami ZAP-a, czyli prawdziwe ataki,
- `--max-minutes 30` - przerywa skan aktywny po 30 minutach.

Skan aktywny tylko z regułami z naszego katalogu zagrożeń, z pająkiem z przeglądarką:

```sh
alert-scanner --scan https://twoja-strona.pl --scope site --mode focused --ajax
```

- `--mode focused` - skan aktywny tylko z regułami z naszego katalogu zagrożeń,
- `--ajax` - pająk z przeglądarką, który wykonuje JavaScript i znajduje więcej podstron.

Skan Juice Shopa z porównaniem do znanych podatności i zapisem surowego raportu ZAP-a:

```sh
alert-scanner --scan http://host.docker.internal:3000 --scope site --mode full --ajax --compare juice-shop --save-report reports/juiceshop.json
```

- `--scan http://host.docker.internal:3000` - adres Juice Shopa na tym samym komputerze, widziany
  z kontenera ze skanerem (`3000` to port aplikacji),
- `--compare juice-shop` - porównuje wynik ze znanymi podatnościami Juice Shopa,
- `--save-report reports/juiceshop.json` - zapisuje surowy raport ZAP-a w podanym pliku.

Analiza gotowego raportu z pokazaniem też odrzuconych alertów, bez zapisu w historii:

```sh
alert-scanner --report reports/zap-full-juiceshop.json --show-filtered --no-store
```

- `--report reports/zap-full-juiceshop.json` - analizuje gotowy raport, bez Dockera i bez skanowania,
- `--show-filtered` - pokazuje też odrzucone alerty,
- `--no-store` - nie zapisuje wyniku w historii (`scans.db`).

Powrót do wcześniejszych wyników:

```sh
alert-scanner --history
alert-scanner --load 3
```

- `--history` - pokazuje listę zapisanych skanów z ich numerami,
- `--load 3` - otwiera zapisany skan o numerze 3.

