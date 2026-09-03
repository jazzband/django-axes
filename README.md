# FakeAccount

Projekt Django realizuje cztery kroki:

1. Rejestracja uzytkownika pod `/register/`.
2. Logowanie pod `/login/` z certyfikatem wygenerowanym przez `generate_cert.py`.
3. Automatyczne uruchomienie `secure_backup.py` po logowaniu tego samego uzytkownika z innego IP. Backup nie jest tworzony ponownie, jezeli aktualny dump bazy ma taki sam hash jak poprzedni.
4. Pobranie odszyfrowanej kopii zapasowej z panelu administracyjnego pod `/admin/download-backup/`.

## Frontend React

Interfejs rejestracji i logowania jest zbudowany w React. Django pozostaje backendem dla sesji, CSRF, walidacji i autoryzacji. Po instalacji zależności zbuduj zasoby frontendu:

```powershell
cd frontend
npm install
npm run build
cd ..
```

Wynik komendy trafia do `fakeaccountapp/static/react/` i jest serwowany przez Django. Po zmianach w `frontend/src/` uruchom ponownie `npm run build`.

## Instalacja

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
```

### Konfiguracja SQLite

PostgreSQL pozostaje domyślną bazą aplikacji. Aby skonfigurować dodatkowe połączenie
PostgreSQL, skopiuj `.env.example` do `.env` i uzupełnij zmienne `POSTGRES_*`.
Połączenie jest dostępne w Django pod aliasem `default`.

Jeżeli zdecydujesz się używać SQLite, stosuj poniższą komendę.
```powershell
python manage.py migrate --database=sqlite
```

## Uruchamianie aplikacji


### HTTP — szybki test w sieci lokalnej

Uruchom serwer nasłuchujący na wszystkich interfejsach sieciowych:

```powershell
python manage.py runserver 0.0.0.0:8000
```

Na tym komputerze otwórz `http://127.0.0.1:8000/register/`. Na urządzeniu w tej samej prywatnej sieci Wi-Fi użyj adresu LAN komputera, na przykład `http://192.168.1.22:8000/register/`.

HTTP jest przeznaczone wyłącznie do krótkich testów w zaufanej sieci. Nie używaj go z prawdziwymi hasłami ani w sieci publicznej, ponieważ dane nie są szyfrowane.

### HTTPS — test z lokalnym certyfikatem

Komenda tworzy lokalne CA oraz certyfikat serwera w formacie PEM zgodnym z OpenSSL:

```powershell
python manage.py generate_cert
```

Powstaja pliki:

- `certs/ca.crt` - lokalny certyfikat CA, ktory trzeba dodac do zaufanych certyfikatow systemu/przegladarki, zeby strona nie byla oznaczana jako podejrzana.
- `certs/key.pem` - klucz serwera.
- `certs/cert.pem` - certyfikat serwera z SAN dla `localhost`, `127.0.0.1`, `::1` oraz wykrytych adresów LAN.
- `certs/openssl.cnf` - konfiguracja SAN dla OpenSSL.

Jezeli `openssl.exe` jest dostepny w `PATH`, komenda uzyje OpenSSL CLI. Jezeli nie jest dostepny, uzyje fallbacku `cryptography` i wygeneruje te same pliki PEM.

Uruchomienie HTTPS:

```powershell
python manage.py runhttps
```

Adres aplikacji:

```text
https://127.0.0.1:8000/register/
```

Adres dla innych urzadzen w tej samej sieci WiFi:

```text
https://192.168.1.22:8000/register/
```

`runhttps` domyslnie nasluchuje na `0.0.0.0:8000`, czyli na localhost i prywatnych adresach sieciowych komputera. Podczas startu wypisuje adresy LAN wykryte na tej maszynie.

Po zmianie sieci WiFi albo adresu IP wygeneruj certyfikat ponownie:

```powershell
python manage.py generate_cert
python manage.py runhttps
```

Jesli automatyczne wykrywanie IP nie trafi we wlasciwy adres, podaj go recznie:

```powershell
python manage.py generate_cert --ip 192.168.1.22
```

Uwaga: ostrzezenie przegladarki zniknie dopiero po zaufaniu `certs/ca.crt` w systemie albo przegladarce. Sam certyfikat lokalny bez zaufanego CA zawsze bedzie traktowany jako podejrzany.

## Backup

Reczne utworzenie zaszyfrowanej kopii:

```powershell
python manage.py secure_backup
```

Wymuszenie nowej kopii mimo duplikatu:

```powershell
python manage.py secure_backup --force
```

Odszyfrowanie do stdout:

```powershell
python manage.py secure_backup --decrypt
```

Zaszyfrowane pliki sa zapisywane w `secure_backups/backup.enc` oraz `secure_backups/backup_meta.json`.

## Przeplyw IP

Po rejestracji aplikacja zapisuje IP startowe w modelu `LoginLog`. Po kazdym udanym logowaniu aplikacja zapisuje kolejne IP. Jezeli IP logowania jest inne niz poprzedni adres tego samego uzytkownika, aplikacja wywoluje `create_secure_backup(skip_duplicate=True)`.

Dla testow przez proxy aplikacja czyta pierwszy adres z naglowka `X-Forwarded-For`, a potem `REMOTE_ADDR`.

## Wylogowanie

Endpoint `/logout/` obsluguje zwykle wejscie GET i przekierowuje do `/login/`.

## Diagnoza timeoutow HTTPS

Jezeli przegladarka pokazuje `ERR_CONNECTION_REFUSED`, serwer `runhttps` nie jest uruchomiony albo zostal zamkniety.

Jezeli przegladarka pokazuje `ERR_TIMED_OUT`, najczestsza przyczyna byla w komendzie `runhttps`: TLS nie moze blokowac glownej petli serwera. Aktualna wersja owija SSL w watku pojedynczego polaczenia, wiec kilka rownoleglych wejsc na `/register/` powinno odpowiadac bez zawieszania.

Szybki test lokalny:

```powershell
python -c "import ssl, urllib.request; print(urllib.request.urlopen('https://127.0.0.1:8000/register/', context=ssl._create_unverified_context(), timeout=5).status)"
```

Poprawny wynik to `200`.

## Testy

```powershell
python manage.py test
```

Test integracyjny backupu wymaga pakietu `cryptography`. Gdy pakiet nie jest zainstalowany, ten test zostanie pominiety.

## Raport uzytkownikow wedlug IP

Raport bazy Django uruchom z katalogu glownego:

```powershell
python scripts\report_python_users_by_ip.py
```

Mozesz podac inna baze jako pierwszy argument. Skrypt wyswietla osobno
uzytkownikow z jednym unikalnym IP oraz tych, ktorzy logowali sie z wiecej niz
jednego IP. Aby wygenerowac ten sam raport z PostgreSQL skonfigurowanego w
Django (`POSTGRES_*` w `.env`), uruchom:

```powershell
python scripts\report_python_users_by_ip.py --postgres
```
