import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional

import aiodns
import aiohttp

# Настройки
SOURCE_URL = "https://antifilter.download/list/domains.lst"
DATA_DIR = Path("data")
STATE_FILE = DATA_DIR / "state.json"
RAW_LIST_FILE = DATA_DIR / "domains_raw.lst"
VALID_DOMAINS_FILE = DATA_DIR / "resolved_domains.txt"

# Параметры DNS-проверки
DNS_SERVERS = ["1.1.1.1"]
CONCURRENCY_LIMIT = 1500  # Количество одновременных DNS-запросов
DNS_TIMEOUT = 1.2        # Таймаут на один запрос в секундах

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def to_punycode(domain: str) -> Optional[str]:
    """Очищает строку и переводит кириллические/IDN домены в Punycode."""
    domain = domain.strip().lower()
    if not domain or domain.startswith("#"):
        return None
    # Убираем возможные протоколы или пути, если попадутся
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        logging.debug(f"Некорректный домен пропущен: {domain}")
        return None


async def fetch_if_changed(session: aiohttp.ClientSession, state: dict) -> Optional[str]:
    """Скачивает файл, если он изменился по ETag, Last-Modified или хешу."""
    headers = {}
    if "etag" in state:
        headers["If-None-Match"] = state["etag"]
    if "last_modified" in state:
        headers["If-Modified-Since"] = state["last_modified"]

    async with session.get(SOURCE_URL, headers=headers) as resp:
        if resp.status == 304:
            logging.info("Файл на сервере не изменился (HTTP 304 Not Modified).")
            return None

        resp.raise_for_status()
        content = await resp.text(encoding="utf-8", errors="ignore")

        # Дополнительная проверка по SHA-256 (если сервер игнорирует If-None-Match)
        new_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if state.get("sha256") == new_hash and VALID_DOMAINS_FILE.exists():
            logging.info("Хеш файла совпадает с предыдущим. Обновление не требуется.")
            return None

        # Обновляем метаданные
        state["etag"] = resp.headers.get("ETag", "")
        state["last_modified"] = resp.headers.get("Last-Modified", "")
        state["sha256"] = new_hash

        RAW_LIST_FILE.write_text(content, encoding="utf-8")
        logging.info(f"Скачан обновленный список ({len(content)} байт).")
        return content


async def check_domain(
    domain: str, resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore
) -> Optional[str]:
    """Проверяет, есть ли у домена A-запись (IPv4)."""
    async with semaphore:
        try:
            await resolver.query(domain, "A")
            return domain
        except aiodns.error.DNSError:
            return None
        except Exception:
            return None


async def resolve_all(domains: list[str]) -> list[str]:
    """Асинхронно проверяет список доменов."""
    resolver = aiodns.DNSResolver(nameservers=DNS_SERVERS, timeout=DNS_TIMEOUT, tries=1)
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    tasks = [check_domain(domain, resolver, semaphore) for domain in domains]
    resolved = []

    total = len(tasks)
    logging.info(f"Начинаем DNS-проверку {total} доменов...")

    for i, task in enumerate(asyncio.as_completed(tasks), 1):
        result = await task
        if result:
            resolved.append(result)
        if i % 10000 == 0 or i == total:
            logging.info(f"Проверено {i}/{total} | Резолвится: {len(resolved)}")

    return sorted(resolved)


async def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    state = load_state()

    resolver = aiohttp.ThreadedResolver()
    connector = aiohttp.TCPConnector(resolver=resolver)
    async with aiohttp.ClientSession(connector=connector) as session:
        content = await fetch_if_changed(session, state)

    if content is None:
        return

    # Парсинг и конвертация в Punycode с удалением дубликатов
    raw_lines = content.splitlines()
    punycode_domains = set()
    for line in raw_lines:
        converted = to_punycode(line)
        if converted:
            punycode_domains.add(converted)

    logging.info(f"Уникальных доменов после обработки Punycode: {len(punycode_domains)}")

    # Проверка резолва
    valid_domains = await resolve_all(list(punycode_domains))

    # Сохранение результата
    VALID_DOMAINS_FILE.write_text("\n".join(valid_domains) + "\n", encoding="utf-8")
    save_state(state)
    logging.info(f"Готово! Сохранено {len(valid_domains)} рабочих доменов в {VALID_DOMAINS_FILE}")


if __name__ == "__main__":
    # На Windows aiodns требует SelectorEventLoop
    if os.name == "nt":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
