# Projekt i implementacja systemu analizy bezpieczeństwa aplikacji internetowych z wykorzystaniem architektury wieloagentowej

Projekt inżynierski, UKEN Kraków, Cyberbezpieczeństwo.
Autorzy: Rudolf Baranko, Dawid Hamryszczak, Konrad Klima.

Program skanuje stronę internetową skanerem OWASP ZAP, odrzuca mało istotne alerty, układa resztę
od najpilniejszych i opisuje je prostym językiem. Ma pomóc komuś, kto prowadzi stronę, ale nie
zajmuje się bezpieczeństwem.

Na razie działa z linii poleceń. Później dojdzie pulpit i animowane wyjaśnienia zagrożeń.

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

`docker compose up -d` podnosi cztery aplikacje treningowe: Juice Shop (`:3000`), DVWA
(`:4280`, przed pierwszym skanem otwórz `/setup.php` i kliknij „Create / Reset Database”),
WebGoat (`:8080/WebGoat`) i bWAPP (`:8081`, przed pierwszym skanem otwórz
`/install.php?install=yes`). bWAPP służy tylko do testu końcowego modelu ML.

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

## Model ML do oceny ryzyka

Reguły w `risk_rules.py` patrzą tylko na `severity` i `confidence` ze skanera. Klasyfikator
ML uczy się na naszych etykietach i widzi też treść znaleziska: czy to endpoint API
czy plik statyczny, czy skaner faktycznie zaatakował, co było w odpowiedzi.

Jednostką jest instancja alertu (URL + parametr). Dane pochodzą z raportów w `reports/`
(nazwa `zap-<tryb>-<aplikacja>.json`), etykiety z plików CSV w `data/labels/`.

```sh
pip install -e ".[ml]"              # scikit-learn, tylko do trenowania i użycia modelu
alert-scanner-ml sheet --calibration 40 --out calibration.csv   # 40 wierszy dla wszystkich
alert-scanner-ml sheet              # data/labels/todo.csv: wiersze, których nikt nie oznaczył
alert-scanner-ml stats              # ile mamy instancji i etykiet
alert-scanner-ml agreement          # zgodność etykiet między osobami
alert-scanner-ml compare            # porównanie modeli-kandydatów (bez aplikacji testowej)
alert-scanner-ml evaluate           # leave-one-app-out, potem test końcowy na bWAPP
alert-scanner-ml train              # zapisuje models/classifier.joblib i drukuje drzewo
alert-scanner-ml diff --report reports/zap-full-bwapp.json   # gdzie model i reguły się różnią
alert-scanner --report reports/zap-full-juiceshop.json --classifier ml
```

Model to płytkie drzewo decyzyjne, które `train` drukuje jako zestaw reguł. Wybieramy go
metodą leave-one-app-out na DVWA, Juice Shopie i WebGoat: trening na wszystkich poza jedną,
sprawdzenie na pominiętej. bWAPP to aplikacja testowa: nie służy do wyboru modelu ani do
treningu. Typy alertów, których model nie widział w treningu, oceniają reguły.

## Centrum sterowania (przeglądarka)

Najprostsze uruchomienie (bez instalacji i bez aktywacji `.venv`):

```sh
python3 run.py
```

Na macOS można też kliknąć dwukrotnie plik `uruchom.command` w Finderze, a na Windowsie `uruchom.bat` w Eksploratorze plików. Przeglądarka otworzy się automatycznie (domyślnie pod `http://127.0.0.1:8000`).

Po zainstalowaniu pakietu (`pip install -e .`) działa też polecenie:

```sh
alert-scanner-web            # otwórz http://127.0.0.1:8000
```

W polu na górze wpisujesz dowolny adres (`przyklad.pl`, `https://moja-strona.com`,
`localhost:3000`), wybierasz tryb i klikasz „Skanuj”. Adresy lokalne są zamieniane na
`host.docker.internal`. Każdy skan wymaga zaznaczenia, że strona należy do użytkownika albo ma zgodę właściciela. Wyniki trafiają do `scans.db`, tak samo jak z linii poleceń.

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
- `ml/dataset.py` - próbki (instancje) z raportów, odciski do dopasowania etykiet
- `ml/features.py` - cechy jednej próbki (bez zależności zewnętrznych)
- `ml/model.py` - drzewo decyzyjne (scikit-learn), trening, porównanie modeli, ewaluacja
- `ml/cli.py` - `alert-scanner-ml`
- `report_html.py` - tymczasowy raport HTML

W `reports/` są dwa gotowe raporty ZAP-a ze skanu Juice Shopa: pasywny i aktywny.
