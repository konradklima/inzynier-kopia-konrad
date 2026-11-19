"""Polskie teksty dla panelu klienta.

ZAP zwraca nazwy, opisy i zalecenia po angielsku. Panel pokazuje zamiast nich
polskie odpowiedniki: nazwę alertu wg identyfikatora reguły, a opis i zalecenie
wg kategorii z catalog.py. Gdy reguły nie znamy, zostaje oryginalna nazwa ZAP-a.
"""

from __future__ import annotations

OWASP_PL = {
    "A01:2021 Broken Access Control": "A01:2021 Błędy kontroli dostępu",
    "A02:2021 Cryptographic Failures": "A02:2021 Błędy kryptograficzne",
    "A03:2021 Injection": "A03:2021 Wstrzykiwanie kodu",
    "A05:2021 Security Misconfiguration": "A05:2021 Błędna konfiguracja zabezpieczeń",
    "A06:2021 Vulnerable and Outdated Components": "A06:2021 Podatne i przestarzałe składniki",
    "A07:2021 Identification and Authentication Failures": "A07:2021 Błędy identyfikacji i uwierzytelniania",
    "A08:2021 Software and Data Integrity Failures": "A08:2021 Błędy integralności oprogramowania i danych",
    "-": "-",
}

# Nazwy alertów wg identyfikatora reguły ZAP.
ALERT_NAMES = {
    "0": "Listowanie katalogów",
    "33": "Listowanie katalogów",
    "10033": "Listowanie katalogów",
    "2": "Ujawnienie prywatnego adresu IP",
    "3": "Identyfikator sesji w adresie URL",
    "10009": "Informacje o serwerze w treści strony",
    "10010": "Ciasteczko bez flagi HttpOnly",
    "10011": "Ciasteczko bez flagi Secure",
    "10015": "Sprawdź nagłówki Cache-Control",
    "10017": "Skrypt dołączany z innej domeny",
    "10020": "Brak nagłówka chroniącego przed clickjackingiem",
    "10021": "Brak nagłówka X-Content-Type-Options",
    "10024": "Dane wrażliwe w adresie URL",
    "10027": "Podejrzane komentarze w kodzie strony",
    "10028": "Przekierowanie na zewnętrzną stronę",
    "10031": "Atrybut elementu kontrolowany przez użytkownika (możliwy XSS)",
    "10035": "Brak nagłówka Strict-Transport-Security (HSTS)",
    "10036": "Serwer ujawnia wersję w nagłówku „Server”",
    "10037": "Serwer ujawnia informacje w nagłówku „X-Powered-By”",
    "10038": "Brak nagłówka Content Security Policy (CSP)",
    "10049": "Treść, którą można zapisać w pamięci podręcznej",
    "10050": "Odpowiedź pobrana z pamięci podręcznej",
    "10051": "Niejednoznaczne ścieżki względne",
    "10054": "Ciasteczko z atrybutem SameSite=None",
    "10055": "CSP: dozwolone style „unsafe-inline”",
    "10058": "Żądanie GET zamiast POST",
    "10062": "Ujawnienie danych osobowych",
    "10063": "Brak nagłówka Permissions Policy",
    "10095": "Dostępna kopia zapasowa pliku",
    "10096": "Ujawniony znacznik czasu",
    "10098": "Błędna konfiguracja współdzielenia między domenami (CORS)",
    "10099": "Ujawniony kod źródłowy PHP",
    "10104": "Test różnych przeglądarek (User Agent)",
    "10109": "Nowoczesna aplikacja internetowa",
    "10110": "Niebezpieczne funkcje JavaScript",
    "10111": "Wykryto żądanie logowania",
    "10112": "Wykryto odpowiedź zarządzającą sesją",
    "10202": "Brak tokenów chroniących przed CSRF",
    "20012": "Kontrola tokenów CSRF",
    "20019": "Przekierowanie na zewnętrzną stronę",
    "20020": "Wersja PHP ze znanymi lukami",
    "40018": "Wstrzyknięcie SQL (SQL Injection)",
    "40038": "Obejście błędu 403",
    "90003": "Brak atrybutu Subresource Integrity",
    "90004": "Brak lub błędny nagłówek Cross-Origin-Resource-Policy",
    "90022": "Ujawnienie błędów aplikacji",
    "90027": "Wykrywanie zbyt szerokich ciasteczek",
    "90033": "Ciasteczko o zbyt szerokim zasięgu",
    "120000": "Informacje w pamięci sessionStorage przeglądarki",
}

# Opis i zalecenie wg klucza kategorii z catalog.py.
CATEGORY_TEXTS = {
    "injection": (
        "Strona przekazuje dane wpisane przez użytkownika wprost do bazy danych lub systemu. "
        "Atakujący może w ten sposób odczytać, zmienić albo usunąć dane, a czasem przejąć serwer.",
        "Używaj zapytań parametryzowanych (przygotowanych) zamiast sklejania tekstu zapytania. "
        "Sprawdzaj i ograniczaj wszystkie dane od użytkownika oraz nadaj aplikacji w bazie tylko niezbędne uprawnienia.",
    ),
    "xss": (
        "Atakujący może wstawić na stronę własny skrypt, który wykona się w przeglądarkach Twoich "
        "odwiedzających. Pozwala to kraść sesje, podszywać się pod użytkowników i zmieniać wygląd strony.",
        "Koduj (escape) wszystkie dane od użytkownika przed wyświetleniem na stronie, "
        "wprowadź nagłówek Content-Security-Policy i używaj sprawdzonych bibliotek do szablonów.",
    ),
    "files": (
        "Osoby z zewnątrz mogą wejść do plików lub katalogów, które nie powinny być publiczne, "
        "np. kopii zapasowych, konfiguracji albo kodu źródłowego.",
        "Wyłącz listowanie katalogów, usuń z serwera kopie zapasowe i pliki tymczasowe "
        "oraz ogranicz dostęp do plików, które nie muszą być publiczne.",
    ),
    "redirect": (
        "Adres strony można zmusić do przekierowania odwiedzających na dowolną inną stronę. "
        "Przestępcy wykorzystują to w phishingu, bo link wygląda na prawdziwy adres Twojej firmy.",
        "Nie przekierowuj na adresy podane przez użytkownika. Dopuszczaj tylko ustaloną listę "
        "docelowych adresów albo ścieżki wewnątrz własnej strony.",
    ),
    "clickjacking": (
        "Złośliwa strona może osadzić Twoją stronę w ukrytej ramce i nakłonić odwiedzających "
        "do kliknięcia czegoś, czego nie zamierzali kliknąć.",
        "Dodaj nagłówek Content-Security-Policy z dyrektywą frame-ancestors "
        "albo nagłówek X-Frame-Options (DENY lub SAMEORIGIN).",
    ),
    "cookies": (
        "Ciasteczka sesji lub identyfikatory logowania są słabo chronione, więc łatwiej je przechwycić "
        "i przejąć konto użytkownika.",
        "Ustaw w ciasteczkach flagi HttpOnly, Secure i SameSite, nie umieszczaj identyfikatora "
        "sesji w adresie URL i ograniczaj zasięg ciasteczek do potrzebnej domeny.",
    ),
    "cross_site": (
        "Inna strona może wysyłać żądania w imieniu zalogowanych użytkowników Twojej strony "
        "albo czytać odpowiedzi, które powinny być prywatne.",
        "Dodaj tokeny CSRF do formularzy i żądań zmieniających dane, ustaw SameSite w ciasteczkach "
        "i ogranicz CORS tylko do zaufanych domen (bez znaku „*”).",
    ),
    "outdated": (
        "Strona używa wersji oprogramowania lub bibliotek, w których znane są luki. "
        "Atakujący mogą wykorzystać gotowe, publicznie opisane metody.",
        "Zaktualizuj przestarzałe składniki do aktualnych, wspieranych wersji "
        "i ustaw regularne sprawdzanie aktualizacji.",
    ),
    "headers": (
        "Serwer nie włącza zabezpieczeń, które przeglądarki potrafią stosować automatycznie. "
        "Sama w sobie nie jest to dziura, ale ułatwia inne ataki.",
        "Skonfiguruj serwer WWW tak, aby wysyłał nagłówki bezpieczeństwa: Content-Security-Policy, "
        "X-Content-Type-Options, Permissions-Policy i Cross-Origin-*.",
    ),
    "info_leak": (
        "Strona zdradza szczegóły techniczne (wersje oprogramowania, adresy wewnętrzne, komunikaty błędów), "
        "które ułatwiają atakującemu przygotowanie ataku.",
        "Ukryj wersje i nagłówki serwera, wyłącz szczegółowe komunikaty błędów dla użytkowników "
        "i usuń komentarze oraz dane wewnętrzne z publicznego kodu.",
    ),
    "third_party": (
        "Strona ładuje skrypty z cudzych serwerów bez sprawdzania ich zawartości. "
        "Jeśli tamten serwer zostanie przejęty, złośliwy kod trafi także na Twoją stronę.",
        "Dodawaj do zewnętrznych skryptów atrybut integrity (Subresource Integrity), "
        "ładuj tylko niezbędne skrypty albo hostuj je samodzielnie.",
    ),
    "transport": (
        "Dane między stroną a odwiedzającymi nie są w pełni szyfrowane, "
        "więc mogą je podejrzeć lub zmienić osoby w tej samej sieci.",
        "Wymuś HTTPS na całej stronie, przekieruj ruch z HTTP i dodaj nagłówek Strict-Transport-Security (HSTS).",
    ),
    "other": (
        "Skaner wykrył nietypowy problem z konfiguracją strony.",
        "Sprawdź ustawienia serwera i aplikacji. Szczegóły techniczne zgłosi osoba odpowiedzialna za stronę.",
    ),
}


def alert_name(rule_id: str, original: str) -> str:
    return ALERT_NAMES.get(rule_id, original)


def owasp(name: str) -> str:
    return OWASP_PL.get(name, name)


def category_texts(key: str) -> tuple[str, str]:
    return CATEGORY_TEXTS.get(key, CATEGORY_TEXTS["other"])
