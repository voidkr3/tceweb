# Relatório de auditoria e reconstrução — Sistema TCE

**Arquivo analisado:** `sistema_web_tce.html` (HTML único, aproximadamente 133 KB / 2.182 linhas).  
**Escopo:** revisão funcional, segurança, integridade, privacidade e arquitetura.  
**Resultado:** a versão antiga não deve ser publicada nem utilizada com dados reais. Foi criada uma nova aplicação cliente-servidor no diretório deste projeto.

## 1. Achados confirmados na versão antiga

| Severidade | Área | Achado | Consequência |
|---|---|---|---|
| Crítica | Autenticação | Contas e senhas de demonstração embutidas no JavaScript (`INITIAL_DB`), incluindo credenciais conhecidas | Qualquer pessoa com acesso ao arquivo pode obter credenciais e entrar |
| Crítica | Autenticação | Login rápido (`quickLogin`) preenchia credenciais de demonstração e chamava o login | Contorno deliberado do fluxo normal de autenticação |
| Crítica | Sessão | `CURRENT_USER` guardava o objeto completo do usuário em `localStorage`, inclusive a senha | Senha e identidade de sessão acessíveis/alteráveis pelo próprio navegador |
| Crítica | Autorização | Restrições de perfil eram aplicadas principalmente ao montar menus e botões | Um usuário podia alterar o JavaScript/armazenamento e chamar operações sem uma barreira de servidor |
| Alta | Persistência | `getData`/`setData` usavam exclusivamente `localStorage` | Dados isolados por navegador/dispositivo, sem sincronização, transações ou controle de concorrência |
| Alta | Neon | O rótulo “Neon PostgreSQL Ready” e o modal DDL não constituíam conexão real com Neon | A interface sugeria uma integração que não existia |
| Alta | XSS | Dados inseridos por usuários eram interpolados em várias strings atribuídas a `innerHTML` | Conteúdo malicioso poderia ser interpretado como HTML/JavaScript |
| Alta | Horas | A verificação facial era uma animação temporizada; a câmera, quando disponível, apenas exibia vídeo | O sistema marcava `biometria_verificada: true` sem reconhecimento ou comparação biométrica |
| Alta | Horas | Duração era arredondada com `Math.round`; intervalos inválidos ou negativos eram convertidos em uma hora | Registro incorreto da carga horária declarada |
| Alta | Aprovação | Aprovar uma declaração novamente somava as horas novamente ao total do contribuinte | Contabilização duplicada |
| Alta | Integridade | Registros eram substituídos como listas inteiras no armazenamento local | Atualizações simultâneas podiam sobrescrever dados uns dos outros |
| Média | Cadastro | Criação de usuário não verificava e-mail duplicado antes de gravar | Registros inconsistentes e falhas no acesso |
| Média | Cadastro | Novo contribuinte criava automaticamente uma conta com senha fixa `123456` | Credencial previsível e reutilizada |
| Média | Exclusão | Remoções não verificavam todos os vínculos com tarefas, horas, compras e demais registros | Possibilidade de referências órfãs e perda de histórico |
| Média | Auditoria | Não havia trilha central de quem criou, alterou, aprovou ou excluiu cada registro | Dificuldade para investigar erros e responsabilizar operações |
| Média | Backup | Não havia rotina central de backup/recuperação | Risco de perda definitiva dos dados do navegador |

## 2. Correções estruturais implementadas na nova versão

- Separação entre interface web, API Node.js e banco Neon PostgreSQL.
- Senhas armazenadas com hash bcrypt (12 rodadas); nenhuma senha é enviada ao navegador na resposta de login.
- Sessão em cookie `HttpOnly`, `SameSite=Strict`, `Secure` em produção e expiração de 8 horas.
- Verificação da conta ativa e do perfil no banco em cada requisição autenticada; desativação e redefinição de senha revogam sessões existentes.
- Troca obrigatória da senha temporária antes de acessar qualquer módulo; política atualizada para mínimo de 8 caracteres, com letra maiúscula, minúscula e número.
- Limitação de tentativas de login, validação de origem nas operações de escrita, Helmet/CSP e ausência de CORS aberto.
- Autorização no servidor por perfil e por registro: contribuinte acessa suas tarefas/horas; escola analisa horas; direção cria solicitações; coordenação administra os módulos autorizados.
- Consultas parametrizadas e nomes de tabelas/campos limitados a listas permitidas.
- Validação de CPF/CNPJ, HTTPS em URLs de documentos, valores, datas, horas e vínculos.
- Banco relacional com chaves estrangeiras, unicidade, verificações de domínio e prevenção de sobreposição de períodos de horas.
- Aprovação de horas limitada a declarações pendentes; total de horas é calculado a partir dos registros aprovados, não incrementado repetidamente em um contador manual.
- Trilha de auditoria para operações relevantes.
- Interface renderiza dados como texto usando APIs DOM; não injeta conteúdo de usuário via `innerHTML`.
- Interface revisada com navegação, formulários, modais, indicadores e tabelas adaptados a telas pequenas; tabelas passam a apresentar os campos em cartões no celular.
- Fluxo de troca de senha atualizado para manter a versão de sessão correta após a alteração da credencial.
- Remoção completa da falsa biometria. O sistema não coleta nem declara reconhecer rostos.
- Remoção de usuários, senhas e cadastros fictícios pré-carregados.

## 3. Módulos incluídos

1. Painel geral e indicadores.
2. Mural de avisos.
3. Tarefas.
4. Cadastro de contribuintes.
5. Fornecedores.
6. Controle financeiro.
7. Compras e notas fiscais.
8. Solicitações de serviço.
9. Declaração e aprovação de horas.
10. Gestão de usuários e permissões.
11. Registro de auditoria.

## 4. Limites e pendências antes de produção

Esta entrega é o **código-fonte de uma nova versão**, não um serviço já hospedado. Não recebi credenciais do Neon nem acesso a uma hospedagem, portanto não foi possível executar testes de integração contra um banco real, criar o primeiro administrador no ambiente do usuário ou publicar uma URL.

Antes de usar dados reais:

1. Criar o projeto Neon e executar `schema.sql`.
2. Configurar as variáveis de ambiente na hospedagem, incluindo `DATABASE_URL`, `JWT_SECRET` e `APP_ORIGIN`.
3. Instalar dependências e criar o primeiro administrador pelo script documentado.
4. Executar testes de ponta a ponta com contas de cada perfil e dados fictícios.
5. Configurar backups automáticos e testar restauração.
6. Definir política de privacidade, finalidade, retenção e acesso aos dados. Como o contexto envolve estudantes e possivelmente menores, coletar somente o estritamente necessário e validar as autorizações institucionais e legais aplicáveis.

**Não migrar automaticamente o `localStorage` antigo.** Primeiro é necessário revisar os dados, remover contas de demonstração e verificar a legitimidade/necessidade de cada dado pessoal. A nova base começa vazia de propósito.

## 5. Verificações executadas nesta entrega

- `node --check server.js`: aprovado.
- `node --check public/app.js`: aprovado.
- `node --check scripts/create-admin.js`: aprovado.
- Política de senha conferida no servidor, interface e script de criação do primeiro administrador: mínimo de 8 caracteres, uma maiúscula, uma minúscula e um número.
- Busca estática na nova interface por `localStorage`, `innerHTML` e credenciais fixas: sem ocorrências de uso para persistência, renderização de dados ou autenticação.
- Não foi possível validar a execução real de SQL, cookies HTTPS, permissões e fluxos integrados sem credenciais e ambiente Neon/hospedagem.

**Conclusão:** a versão antiga tem falhas incompatíveis com uso institucional real. A nova versão corrige a arquitetura e os principais controles no código, mas só deve ser considerada pronta para uso após implantação, testes integrados e validação institucional.


## 6. Alterações da versão 2.2

- Atribuição de tarefas e vínculo de contas usam listas de nomes; UUIDs permanecem internos.
- NFC-e utiliza chave de acesso de 44 dígitos e link para a consulta pública da SEFAZ/RS.
- Exclusão de usuário foi implementada como desativação lógica, com revogação de sessões e preservação de histórico.
- 2FA TOTP para coordenador e vice-coordenador, com segredo criptografado por AES-256-GCM derivado de `JWT_SECRET`, validação no servidor e limitação de tentativas.
- Operações administrativas de escrita/edição/exclusão exigem TOTP para os perfis de coordenação.
- Relatório inicial de horas com filtros, impressão/PDF pelo navegador e exportação CSV.
- Aprovação de horas permanece exclusiva dos perfis da escola e rejeição exige justificativa.

Essas alterações foram verificadas sintaticamente, mas ainda precisam de homologação integrada em ambiente de teste com migração SQL, duas contas administrativas, contas de escola/contribuinte e dados fictícios. Os modelos Word do OneDrive ainda não foram recebidos; a geração documental está limitada ao primeiro relatório padrão até que os modelos sejam fornecidos.
