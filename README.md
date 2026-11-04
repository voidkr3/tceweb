# Portal de Gestão TCE — versão 2.3.3.2

Aplicação web online para gestão do Time de Contribuição Escolar, com API Node.js e Neon PostgreSQL.

## Requisitos

- Node.js 20 ou superior
- Projeto Neon PostgreSQL
- Hospedagem Node.js com HTTPS (Render, Railway, Fly.io ou equivalente)

## 1. Preparar o banco Neon

1. Crie um projeto no Neon.
2. Copie a **pooled connection string** (com SSL) em `DATABASE_URL`.
3. Abra o SQL Editor do Neon.
4. Execute todo o conteúdo de `schema.sql`.

O schema cria as tabelas, chaves estrangeiras, índices e restrições. Não cria usuários nem cadastros fictícios.

## 2. Preparar o projeto localmente

```bash
cp .env.example .env
```

Edite `.env`:

- `DATABASE_URL`: string de conexão do Neon.
- `JWT_SECRET`: segredo aleatório forte, com pelo menos 32 caracteres. Gere com `openssl rand -base64 48`.
- `APP_ORIGIN`: origem exata da aplicação, sem barra final (ex.: `https://tce.exemplo.com`).
- `NODE_ENV=production` quando publicado com HTTPS.

Instale e inicie:

```bash
npm install
npm start
```

Em desenvolvimento local, use `APP_ORIGIN=http://localhost:3000`.

## 3. Criar o primeiro administrador

Com o banco já preparado e `.env` configurado:

```bash
npm run admin:create
```

O script solicitará nome, e-mail e senha. A senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula e número. Não há senha padrão nem conta administrativa pública. O primeiro acesso exige a troca da senha.

## 4. Publicar

Publique o repositório em um serviço que execute Node.js. Configure as mesmas variáveis do `.env` no painel seguro do provedor. Não envie `.env` ao Git, não coloque `DATABASE_URL` ou `JWT_SECRET` no JavaScript do navegador e não publique o banco diretamente.

Configure:

- Build: `npm install`
- Start: `npm start`
- Health check: `/api/health`
- `APP_ORIGIN`: URL HTTPS final da aplicação
- `NODE_ENV`: `production`

A interface e a API são servidas pela mesma origem. Não habilite CORS aberto.

## 5. Atualizar banco de dados (versão 2.2 e 2.3)

Depois de publicar esta versão, abra o SQL Editor do Neon e execute novamente o arquivo `schema.sql`. Ele adiciona as colunas de 2FA e a chave de acesso da NFC-e e permite que registros antigos de compras continuem existindo. Faça um backup antes da alteração.

## 6. Novos recursos da versão 2.2

- Tarefas: seleção do contribuinte pelo nome; o sistema usa o identificador internamente.
- Compras: chave de acesso NFC-e com validação de 44 dígitos e link para consulta no Portal Nacional da NFC-e.
- Usuários: exclusão lógica (desativação), revogação das sessões e preservação do histórico.
- 2FA TOTP: coordenador e vice-coordenador devem configurar um aplicativo autenticador. Operações administrativas de gravação, edição e exclusão exigem o código de seis dígitos.
- Documentos: relatório de horas com filtros por contribuinte, período e situação; impressão/Salvar em PDF pelo navegador e exportação CSV.
- Horas: perfis da escola aprovam ou rejeitam declarações; somente aprovadas entram no total de horas oficiais.

### Configurar o 2FA

1. Entre com a conta de coordenador ou vice-coordenador.
2. Clique em **Configurar 2FA** no menu lateral.
3. No aplicativo autenticador, adicione uma conta manualmente usando a chave exibida. Selecione autenticação baseada em tempo (TOTP).
4. Informe o código de seis dígitos para confirmar.
5. Guarde a chave de configuração em local seguro. O sistema armazena o segredo criptografado no banco.

O segredo TOTP é criptografado com uma chave derivada de `JWT_SECRET`. Se `JWT_SECRET` for trocado depois da configuração, os segredos TOTP existentes não poderão ser descriptografados; planeje a rotação e a reconfiguração do 2FA com antecedência.

## 6. Biblioteca de modelos e emissão de documentos (versão 2.3)

A coordenação pode cadastrar modelos Word `.docx` hospedados no OneDrive/SharePoint. O link precisa permitir visualização/download para qualquer pessoa com o link, pois o servidor baixa o modelo no momento da emissão. São aceitos links HTTPS do OneDrive/SharePoint e arquivos de até 12 MB. Não use links de edição que exijam login.

- Cadastre nome, categoria, link e as tags utilizadas no Word.
- No Word, escreva as tags exatamente no formato `<<nome_completo_contribuinte>>`.
- Na emissão, o sistema preenche tags automáticas e solicita os valores das tags personalizadas.
- O modelo original não é alterado; cada emissão gera um novo arquivo `.docx`.
- Tags desconhecidas ou não cadastradas precisam ser adicionadas ao cadastro do modelo.

Tags automáticas: `<<data_emissao>>`, `<<data_emissão>>`, `<<hora_emissao>>`, `<<nome_emissor>>`, `<<email_emissor>>`, `<<nome_completo_contribuinte>>`, `<<email_contribuinte>>`, `<<cpf_contribuinte>>`, `<<data_nascimento_contribuinte>>`, `<<endereco_contribuinte>>`, `<<situacao_contribuinte>>`, `<<data_inicio>>`, `<<data_fim>>`, `<<total_horas>>`, `<<quantidade_registros>>` e `<<lista_horas_aprovadas>>`. As tags de contribuinte exigem selecionar o cadastro correspondente. As tags de horas usam apenas declarações aprovadas pela escola.

Antes de publicar, execute `MIGRACAO_V2_3.sql` no SQL Editor do Neon. O cadastro, a edição e a desativação de modelos exigem 2FA para coordenador e vice-coordenador.

## 7. Perfis

- **Coordenador principal:** administração de usuários, auditoria, dados financeiros e gestão geral.
- **Vice-coordenador:** gestão operacional, cadastros e administração limitada de contas (não pode criar, alterar ou desativar perfis administrativos); sem acesso ao financeiro.
- **Contribuinte:** mural, tarefas atribuídas e declaração das próprias horas.
- **Escola:** solicitações de serviço e análise das declarações de horas.

As permissões são verificadas no servidor. Esconder um botão na interface não é considerado controle de segurança.

## 8. Cuidados operacionais

- Não use dados reais até concluir os testes de implantação.
- Não reutilize as credenciais de demonstração do HTML antigo.
- Crie contas individuais; não compartilhe usuários.
- Entregue senhas temporárias por canal privado e peça troca no primeiro acesso.
- Desative contas quando a pessoa deixar a função.
- Faça backups e teste a restauração periodicamente.
- Colete o mínimo possível de dados pessoais. Evite documentos, endereço e identificadores quando não forem necessários à finalidade institucional.
- Não há reconhecimento facial nesta versão. A versão antiga apenas simulava uma verificação e não deve ser usada como prova de identidade.

## Estrutura

```text
server.js                 API, autenticação, autorização e regras de negócio
schema.sql                Estrutura do Neon PostgreSQL
public/index.html         Interface
public/app.js             Aplicação cliente
scripts/create-admin.js   Criação segura do primeiro administrador
.env.example              Modelo de configuração (sem segredos)
RELATORIO_AUDITORIA.md    Achados e correções
```

## Limitação desta entrega

O código foi verificado sintaticamente, mas não foi conectado a uma instância Neon nem publicado, pois as credenciais e a hospedagem pertencem ao usuário. É necessário executar a implantação e os testes integrados antes de uso institucional. Não existe migração automática dos dados locais antigos.


## Limitações desta versão 2.2

- A emissão de documentos começa pelo Relatório de Horas Prestadas. Os modelos institucionais em Word do OneDrive ainda precisam ser fornecidos para adaptar cabeçalhos, campos, assinaturas e demais documentos.
- O link da NFC-e abre a consulta do Portal Nacional; a disponibilidade dos dados depende da SEFAZ e da validade da chave informada.
- A exclusão de usuário é lógica: a conta é desativada e as sessões são revogadas para preservar vínculos e histórico.
- O 2FA foi implementado no servidor, mas precisa ser homologado após executar a migração e configurar os aplicativos autenticadores de cada conta.
- Esta entrega ainda não foi conectada à instância Neon nem testada em produção. Faça homologação com dados fictícios antes de cadastrar dados reais.
