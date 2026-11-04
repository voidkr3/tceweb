# Checklist de homologação antes de liberar o TCE

Execute em ambiente de teste, com dados fictícios e uma conta separada para cada perfil. Marque cada item somente após observar o resultado no navegador e no banco.

## Instalação e sessão

- [ ] `/api/health` retorna `status: ok` e `database: connected`.
- [ ] Primeiro administrador é criado pelo script, sem senha padrão no código.
- [ ] Senha errada não autentica; tentativas excessivas recebem limitação temporária.
- [ ] Primeiro acesso obriga a troca de senha; chamadas diretas à API para outros módulos são recusadas antes da troca.
- [ ] Senha fraca é recusada.
- [ ] Atualizar a página mantém a sessão ativa.
- [ ] Sair invalida o cookie de sessão.
- [ ] Desativar usuário impede novas requisições mesmo se o navegador ainda tiver um cookie antigo.
- [ ] Redefinir senha revoga sessões anteriores e exige nova troca.

## Permissões

- [ ] Coordenador acessa módulos administrativos, financeiro, usuários e auditoria.
- [ ] Vice-coordenador acessa usuários com permissões limitadas, mas não acessa financeiro, compras nem auditoria.
- [ ] Contribuinte consulta somente tarefas e horas vinculadas ao próprio cadastro.
- [ ] Contribuinte não consegue enviar horas em nome de outra pessoa alterando o corpo da requisição.
- [ ] Escola cria solicitações e analisa horas, mas não altera cadastros ou financeiro.
- [ ] Operações proibidas retornam HTTP 403 mesmo se chamadas diretamente à API.

## Dados e integridade

- [ ] E-mail duplicado é recusado.
- [ ] CPF/CNPJ inválidos são recusados.
- [ ] URL de documento sem HTTPS é recusada.
- [ ] Referência a fornecedor, contribuinte ou tarefa inexistente é recusada pelo banco.
- [ ] Uma tarefa não pode ser vinculada a declaração de horas de outro contribuinte.
- [ ] Total de horas precisa corresponder exatamente ao intervalo informado.
- [ ] Horário final igual ou anterior ao inicial é recusado.
- [ ] Declarações sobrepostas para o mesmo contribuinte são recusadas pelo banco.
- [ ] Uma declaração só pode ser analisada uma vez.
- [ ] Registros vinculados não são apagados silenciosamente; a exclusão é recusada quando viola integridade.
- [ ] Texto como `<script>alert(1)</script>` é exibido como texto, sem executar código.

## Operação e recuperação

- [ ] Testar criação, leitura, edição e exclusão dos módulos autorizados.
- [ ] Verificar trilha de auditoria após criação, alteração, exclusão, login e aprovação.
- [ ] Configurar backup automático no Neon.
- [ ] Fazer uma restauração de teste em ambiente separado.
- [ ] Confirmar HTTPS, `NODE_ENV=production`, `APP_ORIGIN` correto e `JWT_SECRET` forte.
- [ ] Confirmar que `.env` não foi enviado ao Git nem incluído em artefatos públicos.
- [ ] Validar política institucional de privacidade, retenção e acesso a dados de estudantes.


## 2FA e operações sensíveis — versão 2.2

- [ ] Coordenador configura TOTP com aplicativo autenticador e confirma o código.
- [ ] Vice-coordenador configura TOTP individualmente.
- [ ] A chave TOTP não aparece novamente após ativação e está criptografada no banco.
- [ ] Sem 2FA configurado, operações administrativas de gravação/edição/exclusão são bloqueadas.
- [ ] Com 2FA configurado, operação sem código ou com código inválido é recusada.
- [ ] Código válido permite a operação e gera registro de auditoria.
- [ ] Vice-coordenador não cria, promove ou desativa contas administrativas.
- [ ] Nenhum usuário pode excluir/desativar a própria conta pelo fluxo de administração.
- [ ] Exclusão de usuário desativa a conta, revoga sessões e preserva histórico.

## Usabilidade e novos módulos — versão 2.2

- [ ] Criar/editar tarefa selecionando o contribuinte pelo nome; nenhum ID é solicitado ao operador.
- [ ] A tarefa aparece vinculada ao nome correto do contribuinte.
- [ ] Cadastro de usuário permite selecionar o contribuinte pelo nome, sem exibir UUID.
- [ ] Chave de acesso NFC-e aceita somente 44 dígitos.
- [ ] Link da NFC-e abre a consulta pública da SEFAZ/RS com a chave informada.
- [ ] Relatório de horas filtra por contribuinte, período, atividade e situação.
- [ ] Um único dia pode ser filtrado informando a mesma data como início e fim.
- [ ] Total de horas aprovadas não soma declarações pendentes ou rejeitadas.
- [ ] Impressão do relatório abre a visualização de impressão e permite salvar como PDF.
- [ ] Exportação CSV abre corretamente em planilha.
- [ ] Rejeitar horas exige justificativa.
- [ ] Testar interface em celular e desktop, incluindo tabelas, menus e formulários.


## Testes adicionais — versão 2.3 (biblioteca de documentos)

- [ ] Executar `MIGRACAO_V2_3.sql` no Neon antes do deploy.
- [ ] Instalar dependências com `npm install` (inclui `docxtemplater` e `pizzip`).
- [ ] Configurar 2FA do coordenador e do vice-coordenador.
- [ ] Cadastrar um modelo `.docx` no OneDrive com compartilhamento “Qualquer pessoa com o link pode exibir”.
- [ ] Cadastrar no sistema exatamente todas as tags usadas no Word, sem os delimitadores `<<` e `>>`.
- [ ] Emitir um documento com tag automática `<<data_emissao>>`.
- [ ] Emitir um documento com `<<nome_completo_contribuinte>>`, selecionando um contribuinte.
- [ ] Emitir um documento com `<<total_horas>>`, `<<quantidade_registros>>` e `<<lista_horas_aprovadas>>`, informando período e contribuinte quando aplicável.
- [ ] Confirmar que o arquivo gerado abre no Microsoft Word/LibreOffice e que o modelo original no OneDrive não foi alterado.
- [ ] Testar link sem permissão pública, link expirado, arquivo não-DOCX e modelo com tag não cadastrada; a emissão deve falhar com mensagem compreensível.
- [ ] Confirmar que perfil Escola consegue emitir, mas não cadastrar/editar/desativar modelos.
- [ ] Confirmar que cadastro, edição e desativação de modelos exigem 2FA para coordenação.
