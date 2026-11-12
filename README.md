# Security+ Voucher Watcher

Agente em Python que procura na internet oportunidades de **voucher 100% gratuito para o exame CompTIA Security+** (SY0-701 / SY0-801). Ele descarta descontos parciais, lojas que vendem voucher, campanhas encerradas e cursos gratuitos que não incluem o exame. Só avisa sobre novidades, por:

- e-mail, usando Gmail ou SMTP genérico;
- Telegram, opcionalmente;
- ambos ao mesmo tempo.

Roda automaticamente no **GitHub Actions a cada 8 horas**, sem servidor próprio.

> Adaptado do projeto [VitorHugoFra/certification-automation](https://github.com/VitorHugoFra/certification-automation) (licença MIT), originalmente focado em Microsoft Azure/GitHub.

## O que o agente faz

1. Executa oito pesquisas em português e inglês pela API de busca Tavily.
2. Lê os resultados e, quando possível, a página da campanha.
3. Exige relação direta com o Security+: menção a `Security+`, `Sec+`, códigos como `SY0-701`, ou um voucher válido para qualquer exame CompTIA.
4. Exige indicação forte de voucher/exame gratuito ou desconto de 100%.
5. Penaliza ou rejeita:
   - desconto parcial, como 10% ou 15%;
   - lojas e revendas de voucher pago ("add to cart", "buy now");
   - curso ou treinamento gratuito sem exame;
   - simulados, dumps e material de estudo;
   - fóruns, Reddit e redes sociais;
   - inscrições encerradas, voucher expirado ou prazo passado.
6. Procura o link de inscrição e o coloca diretamente no alerta.
7. Guarda um histórico em `data/seen.json` para não repetir o mesmo aviso.

> Nenhum filtro automático garante elegibilidade ou estoque do voucher. O alerta sempre inclui a fonte para você conferir regras, país, requisitos do programa, quantidade e prazo.

## Onde costumam aparecer vouchers gratuitos de Security+

- Programas de capacitação e empregabilidade em cyber (Per Scholas, NPower, Year Up, Merit America).
- Bolsas e comunidades, como WiCyS.
- Programas para militares e veteranos (Onward to Opportunity e similares).
- Parceiros e academias CompTIA.

Os domínios confiáveis ficam em `config.json` → `trusted_domains`.

## Arquivos principais

```text
security-plus-voucher-watcher/
├── .github/workflows/watch.yml   # agendamento automático
├── .github/workflows/tests.yml   # testes a cada push
├── data/seen.json                # histórico antirrepetição
├── tests/test_watcher.py         # testes dos filtros
├── secplus_voucher_watcher.py    # agente
├── config.json                   # consultas, domínios e perfil
├── requirements.txt
└── .env.example
```

## Configuração no GitHub Actions

### 1. Criar a chave de busca

1. Crie uma conta na [Tavily](https://tavily.com).
2. Abra o painel de API Keys e copie a chave que começa com `tvly-`.

O plano gratuito oferece 1.000 créditos por mês. Esta configuração usa 8 buscas a cada 8 horas, cerca de 720 créditos por mês.

### 2. Preparar o Gmail

1. Ative a verificação em duas etapas na Conta Google.
2. Crie uma **Senha de app** para este agente: https://support.google.com/mail/answer/185833?hl=pt-BR
3. Guarde os 16 caracteres. Não use sua senha normal do Gmail.

### 3. Cadastrar os segredos

No repositório: `Settings` → `Secrets and variables` → `Actions` → `New repository secret`.

| Segredo | Valor |
|---|---|
| `TAVILY_API_KEY` | chave `tvly-...` |
| `GMAIL_USER` | seu endereço Gmail |
| `GMAIL_APP_PASSWORD` | senha de app do Google |
| `ALERT_TO` | e-mail(s) que receberão os avisos, separados por vírgula |

### 4. Permitir que o histórico seja salvo

`Settings` → `Actions` → `General` → `Workflow permissions` → **Read and write permissions**.

### 5. Primeiro teste

1. Abra a aba `Actions`.
2. Escolha **Security+ Voucher Watcher**.
3. Clique em `Run workflow` e veja o log.

## Executar localmente

Requer Python 3.11 ou mais recente.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:TAVILY_API_KEY="tvly-..."
$env:GMAIL_USER="seuemail@gmail.com"
$env:GMAIL_APP_PASSWORD="sua_senha_de_app"
$env:ALERT_TO="seuemail@gmail.com"
python secplus_voucher_watcher.py --dry-run
```

- `--dry-run`: pesquisa e mostra os candidatos, sem enviar alerta nem alterar o histórico.
- `--test-notification`: envia uma mensagem de teste, sem gastar créditos de busca.

## Telegram opcional

1. Converse com `@BotFather` e crie um bot.
2. Envie uma mensagem para o bot e descubra o `chat_id` (por exemplo via `getUpdates`).
3. Adicione os segredos `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID`.

## SMTP diferente do Gmail

Em vez das variáveis `GMAIL_*`, use `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_SSL`, `SMTP_STARTTLS`, `EMAIL_FROM` e `ALERT_TO`.

## Personalizar

Edite `config.json` para mudar as pesquisas, os domínios confiáveis e o perfil de carreira. Cada consulta consome um crédito da Tavily por execução.

Para mudar a frequência, altere o `cron` em `.github/workflows/watch.yml` (horário em UTC).

## Testes

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Os testes cobrem: voucher gratuito ativo, desconto parcial, campanha expirada, outra certificação, revenda paga, curso sem voucher, voucher válido para qualquer exame CompTIA, detecção dos códigos SY0, limpeza de URL, bloqueio de fóruns e escolha do link de inscrição.

## Segurança

- Nunca grave chaves ou senhas no código, no `config.json` ou em commits. Use GitHub Actions Secrets.
- Revogue a senha de app caso suspeite de vazamento.
- O agente não compra exame, não resgata voucher e não preenche inscrição. Ele apenas localiza e alerta.
