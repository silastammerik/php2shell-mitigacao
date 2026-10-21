# Mitigação temporária: desabilitar `session.upload_progress` no PHP (php2shell)

> **Status: 21/10/2026, ~07:40 BRT, antes do release.**
> O PHP agendou release de segurança para **21/10/2026 às 14:00 UTC (11:00 BRT)** corrigindo **CVE-2026-109618** e **CVE-2026-109619** (CVSS 9.2, RCE pré-autenticação).
> Este documento é **paliativo, não correção**. Pacotes de distro e painel (Sury, Remi, EA4, CloudLinux alt-php, Plesk) chegam horas ou dias depois do release oficial. Mantenha a mitigação até o pacote corrigido estar instalado **e** o PHP-FPM/LSAPI reiniciado.

---

## 1. O que se sabe (e o que não se sabe)

- **Componente apontado:** handler de `session.upload_progress` (`php_session_rfc1867_callback`, `ext/session/session.c`), use-after-free no heap, disparado por POST `multipart/form-data` contendo o campo `PHP_SESSION_UPLOAD_PROGRESS`. O recurso vem **ligado por padrão** desde o PHP 5.4.
- **O PHP não confirmou oficialmente** o componente. A ligação com `upload_progress` vem de vazamento e análise de pesquisadores.
- Um pesquisador afirma que são **dois caminhos**: um no `upload_progress` e outro no próprio parser multipart, que roda em qualquer POST multipart independente desta configuração. Ou seja, **desligar `upload_progress` pode fechar só um dos dois**.
- **Versões corrigidas** segundo pesquisadores (confirmar no anúncio do php.net): **8.2.35, 8.3.36, 8.4.27, 8.5.12**.
- **8.1 e anteriores são EOL**: sem correção oficial do PHP.
- **PHP < 5.4** não tem a diretiva. Adicioná-la não faz nada (e não quebra nada).

## 2. Efeito colateral e pegadinhas

- Barras de progresso baseadas em `session.upload_progress` param de funcionar. **O upload em si continua funcionando.** CMS e frameworks modernos geralmente medem progresso no navegador (XHR/fetch), não por esse recurso, mas confira (seção 3.3).
- A diretiva é `PHP_INI_PERDIR`: o cliente pode religar via `.user.ini`, `.htaccess` (mod_php) ou config por domínio no painel. **Só `php_admin_flag`** (pool FPM ou config do Apache) impede o override.
- **`php -i` mostra o CLI**, não o que o site usa. FPM, LSAPI e CGI podem carregar outro `php.ini`. A validação que vale é via HTTP (seção 7).
- Servidor com várias versões: **cada versão tem seu próprio diretório de ini**. Aplique em todas, inclusive nas que "ninguém usa".

## 3. Diagnóstico

### 3.1 Básico (por binário)

```bash
php -v
php -m | grep -ix session                       # sem 'session' carregado => este caminho não se aplica
php -i | grep -i session.upload_progress
php -i | grep -i session.use_only_cookies       # deve ser 1 (padrão)
php --ini                                       # quais arquivos ini foram carregados
```

### 3.2 Inventário de todas as versões instaladas

```bash
for bin in /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php \
           /opt/cpanel/ea-php*/root/usr/bin/php \
           /opt/alt/php*/usr/bin/php \
           /opt/plesk/php/*/bin/php \
           /opt/remi/php*/root/usr/bin/php; do
  [ -x "$bin" ] || continue
  printf '%-45s %-8s upload_progress=%s\n' "$bin" \
    "$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null)" \
    "$("$bin" -r 'var_export(ini_get("session.upload_progress.enabled"));' 2>/dev/null)"
done
```

Leitura: `'1'` = ligado; `'0'` ou `''` = desligado; `false` = diretiva inexistente (PHP < 5.4 ou sem ext session).

FPM (ini global do FPM, **sem** os `php_value`/`php_admin_value` de cada pool):

```bash
for fpm in /usr/sbin/php-fpm* \
           /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
           /opt/plesk/php/*/sbin/php-fpm \
           /opt/remi/php*/root/usr/sbin/php-fpm; do
  [ -x "$fpm" ] || continue
  printf '%-50s ' "$fpm"; "$fpm" -i 2>/dev/null | grep -i '^session.upload_progress.enabled'
done
```

### 3.3 Alguma aplicação usa o recurso?

Ajuste os caminhos de docroot ao seu ambiente (addon domains no cPanel podem ficar fora de `public_html`; Plesk fica em `/var/www/vhosts`).

```bash
grep -rIl --include='*.php' --include='*.js' --include='*.html' --include='*.tpl' --include='*.twig' \
  -e 'PHP_SESSION_UPLOAD_PROGRESS' -e 'upload_progress' \
  /home/*/public_html /var/www 2>/dev/null | head -50
```

Hits em `vendor/` ou variáveis com nome genérico podem ser falso positivo. Se nada relevante aparecer, desligar não tem impacto funcional.

### 3.4 Overrides de cliente que religariam o recurso

```bash
grep -rIl -i 'session.upload_progress' \
  --include='.user.ini' --include='.htaccess' --include='php.ini' \
  /home /var/www 2>/dev/null
```

Overrides específicos de painel estão nas seções 5 e 6.

---

## Variável usada em todos os blocos abaixo

Defina uma vez no shell antes de rodar os comandos das seções 4 a 6:

```bash
CONF='; php2shell (CVE-2026-109618/109619) - mitigacao temporaria, reavaliar apos patch
session.upload_progress.enabled = 0
'
```

O prefixo `zz-`/`99-zz-` no nome do arquivo garante que ele seja lido por último no diretório de scan e vença qualquer ini anterior.

---

## 4. Linux sem painel

### 4.1 Debian/Ubuntu (pacotes da distro ou ondrej/sury)

```bash
for d in /etc/php/*/{fpm,apache2,cgi,cli}/conf.d; do
  [ -d "$d" ] && printf '%s' "$CONF" > "$d/99-zz-php2shell.ini"
done

# testar config e recarregar cada FPM
for v in /etc/php/*/fpm; do
  ver=$(basename "$(dirname "$v")")
  php-fpm"$ver" -t && systemctl reload "php$ver-fpm"
done

systemctl reload apache2 2>/dev/null   # só se usar mod_php (libapache2-mod-php)
```

### 4.2 RHEL / AlmaLinux / Rocky

AppStream (PHP da distro):

```bash
printf '%s' "$CONF" > /etc/php.d/99-zz-php2shell.ini
php-fpm -t && systemctl reload php-fpm
systemctl reload httpd 2>/dev/null     # só se usar mod_php
```

Remi (SCL, várias versões):

```bash
for d in /etc/opt/remi/php*/php.d; do
  printf '%s' "$CONF" > "$d/99-zz-php2shell.ini"
done
systemctl reload 'php*-php-fpm.service'
```

### 4.3 Travar contra override do cliente (recomendado em multi-tenant)

**Pools FPM:**

```bash
for f in /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf; do
  [ -f "$f" ] || continue
  grep -q 'session.upload_progress.enabled' "$f" && continue
  cp -a "$f" "$f.bak-php2shell"                 # .bak não termina em .conf => não é carregado
  echo 'php_admin_flag[session.upload_progress.enabled] = off' >> "$f"
done
```

⚠️ O `echo >>` cai na **última** seção `[pool]` do arquivo. Se um arquivo tiver vários pools, adicione a linha manualmente em cada um. Depois rode `php-fpmX.Y -t` e recarregue o FPM.

**mod_php (Apache):** crie um conf global (Debian: `/etc/apache2/conf-available/zz-php2shell.conf` + `a2enconf zz-php2shell`; RHEL: `/etc/httpd/conf.d/zz-php2shell.conf`):

```apache
<IfModule php_module>
    php_admin_flag session.upload_progress.enabled off
</IfModule>
<IfModule php7_module>
    php_admin_flag session.upload_progress.enabled off
</IfModule>
```

`apachectl -t && systemctl reload apache2` (ou `httpd`).

### 4.4 Containers (imagem oficial `php`)

Drop-in em `/usr/local/etc/php/conf.d/zz-php2shell.ini` via Dockerfile ou bind-mount, depois rebuild/restart do container. `docker exec <ctr> php -i | grep upload_progress` para conferir.

---

## 5. cPanel / WHM (EasyApache 4)

### 5.1 ea-php (todas as versões)

Via WHM: **MultiPHP INI Editor → Editor Mode →** cada versão → adicionar `session.upload_progress.enabled = 0`.

Ou por drop-in (não pertence a nenhum RPM, sobrevive a update e é lido depois do `php.ini`):

```bash
for d in /opt/cpanel/ea-php*/root/etc/php.d; do
  printf '%s' "$CONF" > "$d/zz-php2shell.ini"
done
```

### 5.2 Travar no PHP-FPM (padrão do cPanel)

```bash
mkdir -p /var/cpanel/ApachePHPFPM
Y=/var/cpanel/ApachePHPFPM/system_pool_defaults.yaml
if [ -f "$Y" ]; then cp -a "$Y" "$Y.bak-php2shell"; else echo '---' > "$Y"; fi
grep -q 'session.upload_progress.enabled' "$Y" || \
  echo "php_admin_flag_session_upload_progress_enabled: { name: 'php_admin_flag[session.upload_progress.enabled]', value: 'off' }" >> "$Y"

/usr/local/cpanel/scripts/php_fpm_config --rebuild
/usr/local/cpanel/scripts/restartsrv_apache_php_fpm
/usr/local/cpanel/scripts/restartsrv_httpd
```

O `--rebuild` **não reinicia** o FPM sozinho, por isso o `restartsrv_apache_php_fpm`.

Conferir pools que ficaram **sem** a linha:

```bash
grep -c 'session.upload_progress.enabled' /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf | grep ':0$'
```

Overrides por domínio (YAML de domínio tem precedência sobre o system default):

```bash
grep -l 'upload_progress' /var/cpanel/userdata/*/*.php-fpm.yaml 2>/dev/null
```

⚠️ **Não** use o `rm -rf /var/cpanel/userdata/*/*.php-fpm.yaml` que aparece em tutoriais: apaga customizações de pool de todos os domínios.

### 5.3 CloudLinux (alt-php / PHP Selector, CageFS, mod_lsapi)

alt-php **não** lê o `php.d` do ea-php. Edite o `php.ini` de cada versão e reconstrua:

```bash
for ini in /opt/alt/php*/etc/php.ini; do
  cp -a "$ini" "$ini.bak-php2shell"
  sed -i '/php2shell/,+1d' "$ini"        # idempotente: remove aplicação anterior
  printf '\n%s' "$CONF" >> "$ini"
done
cagefsctl --rebuild-alt-php-ini
```

- Versões antigas (alt-php44 a 53) ignoram a diretiva sem erro.
- Se o "Native" do Selector for ea-php, o 5.1 cobre. Em CloudLinux, rode `cagefsctl --force-update` depois do 5.1 para o CageFS enxergar a mudança.
- A CloudLinux também suporta `/etc/cl.selector/global_php.ini` para aplicar em todas as versões de uma vez. Confira a sintaxe na documentação da sua versão antes de usar.
- Configs por usuário do Selector podem religar o recurso:

```bash
grep -rl 'upload_progress' /var/cagefs/*/*/etc/cl.php.d/ /home/*/.cl.selector/ 2>/dev/null
```

### 5.4 Reinício conforme o handler

| Handler | Comando |
|---|---|
| PHP-FPM | `/usr/local/cpanel/scripts/restartsrv_apache_php_fpm` |
| mod_lsapi / suPHP / CGI | `/usr/local/cpanel/scripts/restartsrv_httpd` |
| LiteSpeed Enterprise | `/usr/local/lsws/bin/lswsctrl restart` (lsphp em daemon mode segura o ini antigo até reiniciar) |

---

## 6. Plesk

### 6.1 PHP do Plesk (`/opt/plesk/php/X.Y`)

```bash
for d in /opt/plesk/php/*/etc/php.d; do
  printf '%s' "$CONF" > "$d/zz-php2shell.ini"
done
systemctl reload 'plesk-php*-fpm.service'
systemctl reload apache2 2>/dev/null || systemctl reload httpd   # recicla processos FastCGI
```

Se a validação HTTP (seção 7) ainda mostrar `'1'` em algum site FPM, troque `reload` por `restart` no serviço daquela versão.

Se preferir editar o `php.ini` principal da versão em vez de drop-in, propague para os domínios com:

```bash
plesk bin php_settings -u
```

### 6.2 PHP do sistema operacional (handler "OS vendor")

Igual à seção 4 (Debian/Ubuntu ou RHEL).

### 6.3 Domínios com override

```bash
grep -l 'upload_progress' /var/www/vhosts/system/*/etc/php.ini /opt/plesk/php/*/etc/php-fpm.d/*.conf 2>/dev/null
```

Corrigir pelo painel (**Websites & Domains → PHP Settings → Additional configuration directives**) ou por CLI:

```bash
plesk db dump psa > /root/psa.$(date +%F-%H%M).sql      # backup antes, como a KB da Plesk recomenda
echo 'session.upload_progress.enabled = 0' > /root/php2shell.ini
plesk bin site --update-php-settings DOMINIO.com.br -additional-settings /root/php2shell.ini
```

⚠️ Teste em **um** domínio antes de rodar em lote: confirme se o comando preserva ou substitui as diretivas adicionais que o domínio já tinha.

### 6.4 Plesk em CloudLinux

Se usar alt-php ou CageFS, aplique também a seção 5.3. Com CageFS, o domínio pode estar preso ao ini global do servidor, o que aqui joga a favor.

---

## 7. Validação via HTTP (obrigatória)

Teste **pelo menos um site por combinação versão × handler** (FPM, LSAPI, FastCGI, mod_php).

```bash
DOM=exemplo.com.br
DOCROOT=/home/USUARIO/public_html          # Plesk: /var/www/vhosts/$DOM/httpdocs
OWNER=$(stat -c '%U:%G' "$DOCROOT")
P="probe-$(openssl rand -hex 8).php"

cat > "$DOCROOT/$P" <<'EOF'
<?php header('Content-Type: text/plain');
echo PHP_VERSION, ' ', PHP_SAPI, ' upload_progress=';
var_export(ini_get('session.upload_progress.enabled')); echo "\n";
EOF
chown "$OWNER" "$DOCROOT/$P"; chmod 644 "$DOCROOT/$P"   # suPHP/FPM por usuário recusam arquivo de root

curl -sk "https://$DOM/$P"
rm -f "$DOCROOT/$P"
```

Esperado: `upload_progress='0'` ou `upload_progress=''`. Se vier `'1'`, existe override (seções 3.4, 5.2, 5.3, 6.3) ou o serviço não foi recarregado.

---

## 8. Camada extra (opcional): WAF

Útil onde o cliente pode ter religado o recurso por `.user.ini`, ou onde você ainda não conseguiu aplicar o ini.

**ModSecurity**: bloquear o campo que aciona o handler (requer `SecRequestBodyAccess On`):

```apache
SecRule ARGS_POST_NAMES "@rx (?i)^PHP_SESSION_UPLOAD_PROGRESS$" \
    "id:91021,phase:2,t:none,deny,status:403,log,msg:'php2shell: campo PHP_SESSION_UPLOAD_PROGRESS em POST'"
```

- Se algum ambiente customizou `session.upload_progress.name`, ajuste o nome.
- **Não cobre** o segundo caminho suspeito (parser multipart).
- Confirme que a regra de `MULTIPART_STRICT_ERROR` do `modsecurity.conf` recomendado (id 200003) está ativa: bloqueia corpo multipart malformado. Pode ajudar se o exploit depender disso, o que não está confirmado.
- cPanel: **WHM → ModSecurity Tools → Rules List → Add Rule**. Plesk: configurações do **Web Application Firewall (ModSecurity)** ou arquivo de regras custom.
- Imunify360, Cloudflare e outros WAFs comerciais costumam publicar virtual patch nesses casos. Verifique com o fornecedor.

---

## 9. Depois do patch

1. **Atualizar** quando o pacote corrigido sair:

   | Ambiente | Comando |
   |---|---|
   | Debian/Ubuntu | `apt update && apt upgrade` |
   | RHEL / Remi | `dnf upgrade 'php*'` |
   | cPanel (EA4) | `dnf upgrade 'ea-php*'` (`yum` em EL7/CL7) |
   | CloudLinux | `dnf upgrade 'alt-php*'` |
   | Plesk | `dnf upgrade 'plesk-php*'` / `apt upgrade`, ou Plesk Installer |

2. **Reiniciar** FPM / LSAPI / LiteSpeed / Apache. Processo antigo continua vulnerável até reiniciar.
3. **Conferir** versões com o inventário (3.2) e o probe HTTP (7).
4. **EOL (≤ 8.1):** sem correção oficial. Migrar, isolar, ou checar backport do fornecedor (CloudLinux alt-php, TuxCare, Ubuntu ESM, RHEL). Até lá, mantenha mitigação + WAF.
5. **Manter desligado?** O próprio manual do PHP recomenda desligar `session.upload_progress` quando não se usa barra de progresso. Se a seção 3.3 não achou uso, considere manter permanente.

### Rollback (se decidir religar)

```bash
rm -f /etc/php/*/*/conf.d/99-zz-php2shell.ini \
      /etc/php.d/99-zz-php2shell.ini \
      /etc/opt/remi/php*/php.d/99-zz-php2shell.ini \
      /opt/cpanel/ea-php*/root/etc/php.d/zz-php2shell.ini \
      /opt/plesk/php/*/etc/php.d/zz-php2shell.ini

# alt-php
sed -i '/php2shell/,+1d' /opt/alt/php*/etc/php.ini && cagefsctl --rebuild-alt-php-ini

# cPanel FPM: remover a linha do system_pool_defaults.yaml e rodar
#   /usr/local/cpanel/scripts/php_fpm_config --rebuild && /usr/local/cpanel/scripts/restartsrv_apache_php_fpm

# Pools FPM sem painel: restaurar *.bak-php2shell ou remover a linha php_admin_flag
# mod_php: remover zz-php2shell.conf (a2disconf no Debian)
```

Depois, recarregar os serviços como nas seções 4 a 6.

---

## 10. Checklist

- [ ] Inventário de versões e SAPIs (3.2)
- [ ] Uso do recurso verificado nas aplicações (3.3)
- [ ] Drop-in / ini aplicado em **todas** as versões
- [ ] Trava via `php_admin_flag` (multi-tenant)
- [ ] FPM / LSAPI / LiteSpeed / Apache recarregados
- [ ] Validação HTTP por combinação versão × handler
- [ ] Overrides de cliente auditados (`.user.ini`, `.htaccess`, YAML cPanel, Selector, Plesk)
- [ ] (Opcional) Regra WAF
- [ ] Patch aplicado assim que disponível + restart dos serviços
- [ ] Decisão registrada: manter desligado ou rollback

---

## Referências

- Anúncio PHP: https://www.php.net/archive/2026.php#2026-10-20-1
- Manual `session.upload_progress`: https://www.php.net/manual/en/session.upload-progress.php
- Patchstack: https://patchstack.com/articles/php-major-vulnerability-alert-10-2026/
- Phoenix Security (dois caminhos suspeitos): https://phoenix.security/php-core-rce-cve-2026-109618-109619-critical-remote-code-execution/
- Pesquisa independente (versões afetadas/corrigidas): https://github.com/ikow/php2shell-poc
- cPanel, php.ini com PHP-FPM: https://docs.cpanel.net/knowledge-base/web-services/how-to-manage-your-php.ini-directives-with-php-fpm/
- Plesk, alterar PHP de domínios via CLI: https://support.plesk.com/hc/en-us/articles/12377477741335
