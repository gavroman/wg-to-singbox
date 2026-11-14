#!/usr/bin/env bash
# Разворачивает официальный 3x-ui через SSH в host-сети с прежними volumes.
set -euo pipefail

SSH_TARGET=''
SSH_PASSWORD=''
SSH_KEY=''
SSH_PORT=22
PANEL_USER=''
PANEL_PASSWORD=''
PANEL_PORT=2053
IMAGE='ghcr.io/mhsanaei/3x-ui:latest'

usage() {
  cat <<'USAGE'
Использование:
  ./setup-3x.sh -s user@host -u LOGIN -w PASSWORD [параметры]

  -s user@host  SSH-сервер (также поддерживает alias из ~/.ssh/config)
  -p PASSWORD   SSH-пароль; без него используются SSH-ключи/agent/config
  -i FILE       файл SSH-ключа
  -S PORT       SSH-порт (по умолчанию 22)
  -u LOGIN      логин администратора 3x-ui
  -w PASSWORD   пароль администратора 3x-ui
  -P PORT       порт панели (по умолчанию 2053)
  -I IMAGE      официальный образ ghcr.io/mhsanaei/3x-ui:TAG
                (по умолчанию ghcr.io/mhsanaei/3x-ui:latest)
  -h            справка

Пример:
  ./setup-3x.sh -s root@1.2.3.4 -i ~/.ssh/id_ed25519 \
    -u myadmin -w 'my-long-password'

Нужны Bash и Docker на Linux-сервере, доступ к Docker без sudo.
При SSH-пароле локально нужен sshpass. Пароли в аргументах могут попасть
в историю shell; вместо литералов можно передать значения shell-переменных.
Ключ сервера проверяется через known_hosts (новый ключ принимается автоматически).

Контейнер 3x-ui заменяется без резервной копии. Используются volumes:
  3x-ui-db:/etc/x-ui, 3x-ui-cert:/root/cert, 3x-ui-acme:/root/.acme.sh
На новом сервере они создаются. На существующем сервере mounts проверяются.
База сохраняется; выбранная версия панели может выполнить её миграцию.
Порт и учётные данные панели меняются, настройки TLS и URL-пути сохраняются.
Порты inbound'ов должны быть свободны на хосте.
USAGE
}

fail() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
valid_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

while getopts ':s:p:i:S:u:w:P:I:h' opt; do
  case "$opt" in
    s) SSH_TARGET=$OPTARG ;;
    p) SSH_PASSWORD=$OPTARG ;;
    i) SSH_KEY=$OPTARG ;;
    S) SSH_PORT=$OPTARG ;;
    u) PANEL_USER=$OPTARG ;;
    w) PANEL_PASSWORD=$OPTARG ;;
    P) PANEL_PORT=$OPTARG ;;
    I) IMAGE=$OPTARG ;;
    h) usage; exit 0 ;;
    :) fail "флаг -$OPTARG требует значение" ;;
    *) usage >&2; exit 1 ;;
  esac
done
shift "$((OPTIND - 1))"
[[ $# == 0 ]] || fail 'лишние позиционные аргументы'
[[ -n "$SSH_TARGET" && "$SSH_TARGET" != -* ]] || fail 'задай -s user@host'
[[ -n "$PANEL_USER" ]] || fail 'задай логин панели через -u'
[[ -n "$PANEL_PASSWORD" ]] || fail 'задай пароль панели через -w'
valid_port "$SSH_PORT" || fail 'SSH-порт должен быть от 1 до 65535'
valid_port "$PANEL_PORT" || fail 'порт панели должен быть от 1 до 65535'
SSH_PORT=$((10#$SSH_PORT))
PANEL_PORT=$((10#$PANEL_PORT))
[[ "$IMAGE" =~ ^ghcr\.io/mhsanaei/3x-ui:[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]] ||
  fail 'ожидается официальный образ ghcr.io/mhsanaei/3x-ui:TAG'
command -v ssh >/dev/null 2>&1 || fail 'не найден ssh'
if [[ -n "$SSH_KEY" ]]; then
  [[ -r "$SSH_KEY" ]] || fail "SSH-ключ недоступен: $SSH_KEY"
fi
if [[ -n "$SSH_PASSWORD" ]]; then
  command -v sshpass >/dev/null 2>&1 || fail 'для SSH-пароля установи sshpass'
fi

SSH_OPTS=(-T -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new)
if [[ -n "$SSH_KEY" ]]; then SSH_OPTS+=(-i "$SSH_KEY"); fi

run_remote() {
  if [[ -n "$SSH_PASSWORD" ]]; then
    SSHPASS="$SSH_PASSWORD" sshpass -e ssh "${SSH_OPTS[@]}" "$SSH_TARGET" 'bash -s'
  else
    ssh "${SSH_OPTS[@]}" "$SSH_TARGET" 'bash -s'
  fi
}

# Значения передаются в stdin как Bash-литералы, а не вставляются в SSH-команду.
# Это сохраняет кавычки, $, пробелы и переводы строк в паролях.
remote_script() {
  printf 'PANEL_USER=%q\nPANEL_PASSWORD=%q\nPANEL_PORT=%q\nIMAGE=%q\n' \
    "$PANEL_USER" "$PANEL_PASSWORD" "$PANEL_PORT" "$IMAGE"
  cat <<'REMOTE'
set -euo pipefail
fail() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail 'Docker не установлен на сервере'
[[ "$(docker info --format '{{.OSType}}')" == linux ]] ||
  fail 'нужен доступ к Docker Engine на Linux'

# Не подменяем существующую базу пустым named volume при другом mount.
EXISTS=false
if docker container inspect 3x-ui >/dev/null 2>&1; then
  EXISTS=true
  for spec in '3x-ui-db:/etc/x-ui' '3x-ui-cert:/root/cert' '3x-ui-acme:/root/.acme.sh'; do
    volume=${spec%%:*}
    destination=${spec#*:}
    actual=$(docker container inspect --format \
      "{{range .Mounts}}{{if eq .Destination \"$destination\"}}{{.Type}}:{{.Name}}{{end}}{{end}}" 3x-ui)
    [[ "$actual" == "volume:$volume" ]] ||
      fail "mount $destination отличается от ожидаемого $volume; контейнер не изменён"
  done
fi

echo '>> Загружаю официальный образ...'
docker pull "$IMAGE"
for volume in 3x-ui-db 3x-ui-cert 3x-ui-acme; do
  docker volume create "$volume" >/dev/null
done

if [[ "$EXISTS" == true ]]; then
  echo '>> Останавливаю 3x-ui...'
  docker stop 3x-ui >/dev/null
fi

echo '>> Настраиваю учётные данные и порт панели...'
# Основной процесс остановлен: CLI меняет ту же базу без параллельной записи.
# Вывод CLI скрыт, чтобы логин и пароль не попадали в лог скрипта.
if ! docker run --rm --network none \
  -v 3x-ui-db:/etc/x-ui \
  --entrypoint /app/x-ui "$IMAGE" setting \
  -username "$PANEL_USER" -password "$PANEL_PASSWORD" -port "$PANEL_PORT" \
  >/dev/null 2>&1; then
  fail 'не удалось настроить базу; существующий контейнер оставлен остановленным (если он был)'
fi

if [[ "$EXISTS" == true ]]; then docker rm 3x-ui >/dev/null; fi
echo '>> Запускаю 3x-ui в host-сети...'
docker run -d \
  --name 3x-ui \
  --network host \
  --restart unless-stopped \
  -v 3x-ui-db:/etc/x-ui \
  -v 3x-ui-cert:/root/cert \
  -v 3x-ui-acme:/root/.acme.sh \
  -e XUI_PORT="$PANEL_PORT" \
  -e XUI_ENABLE_FAIL2BAN=false \
  "$IMAGE"

sleep 2
state=$(docker container inspect --format '{{.State.Running}}:{{.RestartCount}}' 3x-ui)
[[ "$state" == true:0 ]] ||
  fail 'контейнер остановился или перезапускается; проверь docker logs --tail 50 3x-ui'
printf '>> Контейнер запущен. Порт панели: %s. TLS и URL-путь — из сохранённых настроек.\n' "$PANEL_PORT"
echo '>> Проверь запуск панели и Xray: docker logs --tail 50 3x-ui'
echo '>> Inbound-ы и клиенты находятся в прежнем volume 3x-ui-db.'
REMOTE
}

printf '>> Сервер: %s; порт панели: %s; образ: %s\n' "$SSH_TARGET" "$PANEL_PORT" "$IMAGE"
remote_script | run_remote
