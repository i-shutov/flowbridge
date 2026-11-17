# FlowBridge — решение владельца: только внутреннее использование

**Дата:** 17 ноября 2026. **Точный выбор владельца:** «пока только внутреннее».

Это решение относится к способу **использования и распространения продукта**, а не автоматически к степени технической готовности. Оно дополняет решение от 17.11 о **Windows 10 Pro 22H2 x64 ONLY**: Windows 11 и macOS переносятся на следующие релизы.

## Текущая политика продукта

- **Внутреннее использование / закрытый pilot** владельцем и явно уполномоченными внутренними участниками. Возможна передача точного тестового installer ZIP внутри санкционированной команды для QA, с фиксированными SHA-256 и ограничениями доступа. **Не считать эту политику автоматическим разрешением на развёртывание или рассылку**: нужен отдельный internal A6 security/privacy acceptance и explicit A7 internal-deployment GO.
- **Никакой публичной дистрибуции**: не создавать публичный GitHub Release, tag с маркетинговым выпуском, сайт с установщиком, публичный download link, release notes для внешней аудитории, third-party/customer redistribution, публичный package feed. Не выдавать неподписанный инженерный пакет за production.
- **Выбор MIT / Apache-2.0 / proprietary own-code license отложен** до решения о внешнем распространении. Текущее исходное `LICENSE` («No separate open-source license has been selected») **оставить неизменным**. Решение «internal-only» **не является автоматически новой лицензией** и не переоформляет права на сторонние компоненты.
- Существующий публичный репозиторий / доступные GitHub Actions artifacts **не становятся приватными от записи об internal-only**; не загружать туда новые оригинальные пользовательские ZIP, ssh key/hostnames/path/password/token/diagnostics. Если необходима реальная приватность артефактов, обеспечить права репозитория и закрытое хранилище отдельным решением.
- Требования лицензий внешних библиотек, нативных SDK, runtime, ownership и C++/Windows security **не отменяются**. Их необходимо проверить в подходящем для ограниченного внутреннего использования масштабе, прежде чем передавать пакет иным внутренним пользователям.
- Win10 Pro 22H2 прошла основной срок поддержки; для любых длительных внутренних пилотов требуется проверка фактических Windows security/ESU updates и ограничений тестового стенда. Не отключать SmartScreen/Defender, UAC, firewall, DNS, BCD, test-signing или ставить WFP/NDISRD на рабочую машину ради beta.

## Что доказано в неизменяемом кандидате

| Факт | Статус |
| --- | --- |
| Source SHA | `86583a1a0487b9d383c0122b24558e620bde5b9c` |
| Original `0.3.0-beta.2` kit ZIP SHA256 | `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae` |
| Installer SHA256 | `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4` |
| A0–A3 Win10 user-mode | **PASS** на independently reviewed owner V4 100/100 и V5 26/26, без физического независимого повторного запуска |
| Candidate [CI #43883696169](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) | 11/11 SUCCESS |
| A5 original technical BOM / RustSec | [CI #43936785163](https://github.com/i-shutov/flowbridge/actions/runs/43936785163) 4/4 SUCCESS |
| A6 exact original bytes/PE | [CI #44041579615](https://github.com/i-shutov/flowbridge/actions/runs/44041579615) 4/4 SUCCESS |
| Внешняя лицензия | **DEFERRED** — не обязательный отдельный выбор для текущей собственной внутренней разработки, но обязательный до внешней дистрибуции |
| A5 внутренние права/условия зависимостей, A6 full security/privacy | **OPEN**, независимо от технических PASS |
| A7 external publication | **PROHIBITED / NOT_REQUESTED** |
| A7 internal deployment | **NOT_YET_AUTHORIZED**; «только внутреннее» — выбор политики, не GO на раздачу или установку |

**Текущий разрешённый тип работы:** дальнейшая внутренняя разработка и контролируемые тесты исходных артефактов на ранее разрешённых стендах. **Внутренний выпуск/распространение вне проверенного QA-хоста** требует отдельного документированного разрешения.

## Два раздельных будущих маршрута

**Текущий internal-only Win10 beta.2:** провести ограниченное A5 internal-use license/dependency/runtime assurance, независимый P0/security/privacy A6 и отдельный internal A7 deployment GO. Для этого **не нужно выбирать публичную лицензию собственного кода сейчас**. Не создавать GitHub Release/tag.

**Будущее внешнее распространение / поддержка Win11/macOS:** снова открыть выбор лицензии собственного кода и legal/runtime redistribution [#78](https://github.com/i-shutov/flowbridge/issues/78); оформить отдельный release candidate/политику внешней дистрибуции, вернуться к платформенному QA [#79](https://github.com/i-shutov/flowbridge/issues/79). Internal decision нельзя использовать как условие «public distribution approved».

**Отдельный Windows 10 1.0:** WFP/ALE signed driver/kernel socket authority, native G2 and physical packet no-DIRECT/DNS/UDP remain `NO_GO`. Политика internal-only не даёт разрешения на небезопасную загрузку драйвера на владельческий стенд.

**Обязательные машинные статусы:** `distribution_mode=INTERNAL_ONLY`, `public_distribution_authorized=false`, `public_license_selection_deferred=true`, `internal_deployment_approved=false`, `release_accepted=false`, `github_release_created=false`, `release_tag_created=false`, `wfp_g2_accepted=false`.
