# FlowBridge: handoff для оркестрирующего агента — 28.11.2026

**Решение: NO GO для внутреннего 0.3.0; A7 не принято.** Этот документ и
[генеральный план](../../../../RELEASE_1_0_PLAN.md) фиксируют результаты и открытые
работы. Никакой релиз, тег или публикация установщика не выполнялись.

## База и содержимое ветки

- Историческая ветка плана основана на `c847def907530ef3ac436075a142a3e63dbd088f`.
- Оригинальный private beta.4 — build `46040903481`, attempt 1, source
  `c8881dada43e3183a0340dc823105bdcdac71171`, tree
  `ce336e83bb724a65bf512e79e286c97fb0cb3190`. Его байты не менялись.
- Продуктовые изменения сохранены как [runtime patch](runtime-experimental.patch)
  и [Win32/harness patch](win32-experimental.patch), **применимые к оригинальному
  source beta.4**, а не как замена файлов текущей документальной ветки. Проверка
  `git apply --check` на исходном candidate tree прошла для обоих. До выпуска
  перенести патчи в ветку продукта, провести review и зафиксировать source/tree.
- Испытанная экспериментальная комбинация: пересобранный GUI Release SHA-256
  `41a20a4116a757bfb67ba19a419e32d55662f97bafb8570329024c2b770c2bc6` и
  FFI **debug** SHA-256
  `89bf4f4b7e811869aaa193d703365d23f58d1e5394b7f30828c723af5bad3e61`.
  Это не установщик кандидата и не production/release-сборка.

## Результаты

| Проверка | Результат и граница |
| --- | --- |
| Original beta.4 desktop preflight | PASS в активном Win11 Admin SessionId 2: desktop, isolation и pinned bytes. |
| Original Win32 smoke | FAIL с `native_command_failed`: DPI-unaware harness неверно измерил физический зазор; диагностическая копия затем обнаружила отдельное пересечение SSH-справки и Save на 1 px. Первичный отчёт сохранён. |
| Локальные исправления | В копии исправлены вертикальная геометрия, сводка Apps, DPI-aware harness и Enter для owner-drawn кнопок. При недоступности managed SSH или исчерпании capacity новые запросы отклоняются сразу; клиент должен повторить запрос. `grace_ms` оставлен для совместимости интерфейса, но больше не удерживает новые запросы. |
| Очередь | До исправления два закрытых клиента вызвали два поздних target accept; проверочный маркер не был доставлен. В исправленной копии оба запроса отклонены, после восстановления поздних accept не было; binary SOCKS5h echo и EOF снова прошли. Проверить другие гонки, в том числе закрытие во время upstream connect, и сохранить корректный TCP half-close. |
| Runtime и GUI | 17 runtime tests PASS; modified Win32 harness на исправленных GUI/FFI при DPI 120 PASS. Один промежуточный run имел `GUI Apply failed`; причина не установлена, два последующих smoke прошли. |
| Последний GUI SSH | PASS в изолированном loopback: Microsoft-signed sshd, GUI-owned системный OpenSSH, authentication и binary echo/EOF; wrong host key, missing key, unsigned backend, outage/recovery и Stop проверены. Это не pool512 и не full security/privacy acceptance. |
| Ручная компактная проверка | Все пять страниц/режимов и modal осмотрены на действительном desktop при DPI 120; Save, Apply через Enter, Start/Stop, Tab и Cancel с сохранением родительского draft проверены. Окно доведено до минимального размера через системное меню; снимок имеет размер 771 × 538 логических пикселей. |
| Accessibility | FAIL: фокус на SSH host control ID 231 читается деревом доступности как «Макс. пауза, мс». Исправить и проверить все поля, клавиатурный обход, modal и обе геометрии. |
| Очистка | Тестовые установки удалены штатным uninstaller, принадлежащие процессы/listeners остановлены, временные SSH-ключи удалены, профили перенесены в закрытые evidence directories. Повторный preflight подтвердил isolation baseline и оригинальные candidate pins. |

Промежуточные отчёты, снимки, профили и сырые журналы остаются в закрытом
каталоге VPS; в ветку они не включены. Пути к приватным evidence и SHA-256 двух
sanitized summary зафиксированы в генеральном плане. Не публиковать ключи,
профили, адреса из них, сырые логи или бинарные пакеты.

## Следующие действия

1. Применить патчи к правильной продуктовой базе, проверить и доработать логику
   отказа при перегрузке и все гонки отмены, проверить обратную совместимость
   поведения очереди. Исправить доступное имя SSH host и провести review.
2. Создать новый зафиксированный private candidate с source/tree/manifest и
   hashes. Повторить на его байтах установку, upgrade/remove/preservation,
   DPI-aware Win32 smoke, ручные normal/compact/a11y, GUI SSH и отрицательные
   проверки. Выяснить воспроизводимость промежуточного Apply timeout.
3. Повторить настоящий managed pool 4 × 128 / 512 held, overload, recovery и
   cleanup на FFI нового пакета: прежний P3 относится к original beta.4.
4. Закрыть A5/A6 по фактическому составу и конкретному source/пакету, выполнить
   актуальный dependency/security review; подготовить handoff и независимое
   решение A7. Предыдущий RustSec frozen beta.3 не переносится автоматически.
5. WFP/G2 и macOS вести отдельно; Win10, Windows policies и SSH trust не менять.
   Публичные пакеты, Release и тег не создавать в рамках этого handoff.
