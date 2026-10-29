**5.b.i: `@precision`** 
O valor é `@precision low`. Indica que a query tem uma taxa elevada de falsos positivos, ou seja, muitos dos alertas podem não ser problemas reais. Por isso estas queries não vêm na _suite_ padrão do code scanning e os resultados precisam de revisão manual. Os valores possíveis são `low`, `medium`, `high` e `very-high`.

**5.b.ii: como decide que um campo contém uma password** 
A decisão baseia-se apenas no **nome da variável**. A query usa a classe `PasswordVariable`, definida em HardcodedCredentials.qll:69:

```ql
this.getName().regexpMatch("(?i)(encrypted|old|new)?pass(wd|word|code|phrase)(chars|value)?")
```

Ou seja, uma variável conta como password se o nome inteiro (sem distinguir maiúsculas de minúsculas) for algo como `password`, `passwd`, `passcode`, `newPassword`, `passwordValue`, etc. Depois, o predicado `passwordFieldAssignedHardcodedValue` (em HardcodedPasswordField.ql) exige três condições:

1. a variável é um **campo** da classe (`f instanceof Field`);
2. é-lhe atribuída uma **constante de compilação** (`CompileTimeConstantExpr`), por exemplo um literal;
3. essa constante **não é a string vazia** `""`.

**5.b.iii: é análise de fluxo de dados?** 
Não. É uma análise **sintática/estrutural** sobre a AST: verifica o nome do campo e se o valor atribuído diretamente é uma constante. Não importa `DataFlow` nem `TaintTracking`, nem segue o valor para onde é usado. Se a password passasse por outra variável ou por um método antes de chegar ao campo, a query já não a detetava.


**5.d.i: estrutura JWT e operação criptográfica**
Um JWT tem três partes codificadas em Base64URL e separadas por pontos: `header.payload.signature`.

- **Header:** JSON com o tipo e o algoritmo, por exemplo `{"alg":"HS512","typ":"JWT"}`.
- **Payload:** as _claims_, ou seja, os dados sobre o utilizador. Aqui são `{"admin":"false","user":"Jerry"}` mais o `iat`. Só está codificado, não cifrado, por isso qualquer pessoa o consegue ler.
- **Signature:** `HMAC-SHA512(base64url(header) + "." + base64url(payload), segredo)`.

A operação que depende do segredo é o **HMAC (HS512)**, que é uma assinatura simétrica. A mesma chave serve para **gerar** a assinatura ao emitir o token e para a **verificar** quando o token volta ao servidor. Garante a **integridade e autenticidade** do token, mas não a confidencialidade.

**5.d.ii: porque é que a query não o detetou** 
A classe `PasswordVariable` só aceita nomes que correspondam **na totalidade** a:

```
(?i)(encrypted|old|new)?pass(wd|word|code|phrase)(chars|value)?
```

Em CodeQL, o `regexpMatch` está implicitamente ancorado: tem de corresponder ao nome todo, não apenas a uma parte. O único prefixo permitido é `encrypted`, `old` ou `new`. Como `JWT_PASSWORD` começa por `JWT_`, que não está nessa lista, a correspondência falha e o campo nunca é considerado um `PasswordVariable`. O campo `PASSWORD` da linha 45 corresponde exatamente, porque a regex ignora maiúsculas e minúsculas e não tem prefixo.

Há ainda uma limitação mais geral: a query baseia-se apenas em nomes. Uma chave guardada numa variável chamada `secret`, `key` ou `signingKey` também nunca seria detetada.

**5.d.iii: classificação** 
É um **falso negativo**. Existe de facto uma vulnerabilidade (um segredo criptográfico embutido no código), mas a ferramenta **não a reportou**. 

**5.e: o que o atacante consegue fazer** 
Com o `JWT_PASSWORD`, o atacante consegue **forjar tokens válidos com quaisquer claims**, sem precisar de credenciais nem de fazer login:

- **Escalar privilégios:** gerar um token com `"admin": "true"` e aceder a funções de administração.
- **Fazer-se passar por qualquer utilizador:** pôr `"user": "Tom"` ou outro nome qualquer e agir em nome dessa pessoa. Não está limitado ao Jerry, que é o único cuja password conhece.
- **Persistência:** criar tokens sem expiração, ou com `iat`/`exp` manipulados. Continuam válidos mesmo que as passwords dos utilizadores mudem, até o segredo ser rodado.
- **Contornar a autenticação por completo:** o endpoint de login deixa de ter qualquer importância.



## A.5.f – Path Traversal (CWE-22)

Foi utilizada a interrogação `Security/CWE/CWE-022/TaintedPath.ql`, que usa análise de fluxo de dados para encontrar dados controlados pelo utilizador usados na construção de caminhos de ficheiros.

**Resultado em `ProfileUploadBase.java`:** linha 52, *"This path depends on a user-provided value."*

Caminho reportado pelo CodeQL:

| # | Localização | Descrição |
|---|-------------|-----------|
| 1 | `ProfileUpload.java:41` | **Source:** parâmetro `fullName` do pedido HTTP |
| 2 | `ProfileUpload.java:43` | `fullName` é passado ao método `execute()` |
| 3 | `ProfileUploadBase.java:40` | `fullName` chega ao método `execute()` |
| 4 | `ProfileUploadBase.java:52` | **Sink:** criação do ficheiro com `createNewFile()` |

```java
var uploadedFile = new File(uploadDirectory, fullName);
uploadedFile.createNewFile();
FileCopyUtils.copy(file.getBytes(), uploadedFile);
```

**Vetor de ataque:** o endpoint `POST /PathTraversal/profile-upload` serve para carregar a fotografia de perfil, que devia ser guardada em `.../PathTraversal/<username>/<fullName>`. Como o valor de `fullName` é enviado pelo utilizador e não é validado, um atacante pode intercetar o pedido e colocar sequências `../` nesse campo, por exemplo `fullName = ../../../tmp/malicioso`. Cada `../` sobe um nível na árvore de diretórios, pelo que o ficheiro é escrito **fora da pasta prevista**, num local à escolha do atacante.

Como o atacante controla o caminho e o conteúdo do ficheiro, pode criar ou sobrescrever ficheiros em qualquer pasta onde a aplicação tenha permissão de escrita, por exemplo ficheiros de configuração ou de outros utilizadores. Em certos cenários pode chegar a executar código no servidor, por exemplo colocando um script num diretório servido pela aplicação.



## A.5.g – Correção e reanálise

A base de dados foi regenerada (`codeql database create webgoat-database --language=java --build-mode=none --overwrite`) e a interrogação `TaintedPath.ql` foi novamente executada.

**Resultado:** o CodeQL **deixou de assinalar** a vulnerabilidade no método `execute()`. Os alertas anteriormente reportados em `createNewFile()` e `FileCopyUtils.copy()` deixaram de aparecer para todos os endpoints que invocam este método.

**Justificação:** `getCanonicalPath()` devolve o caminho absoluto normalizado, com as sequências `../` e os links simbólicos resolvidos. A comparação com `startsWith(uploadDirectory.getCanonicalPath() + File.separator)` garante que o ficheiro final fica dentro do diretório de upload. A inclusão de `File.separator` evita que um diretório como `.../rodrigo-evil` seja aceite como prefixo de `.../rodrigo`. As bibliotecas do CodeQL reconhecem este padrão como *sanitizer guard* de path traversal, pelo que o fluxo de dados contaminados é interrompido antes de chegar aos *sinks*.

Os resultados que permanecem no ficheiro (`cleanupAndCreateDirectoryForUser()`, linhas 78, 79 e 81) já existiam antes da alteração e têm como *source* o `username`. Esse valor é obtido da sessão autenticada (`@CurrentUsername` → `@AuthenticationPrincipal`) e não do pedido HTTP, e está restrito ao padrão `[a-z0-9-]*`. Trata-se de falsos positivos não relacionados com o método `execute()`.


## A.5.h – Classificação OWASP

**OWASP Top 10:2025:** a vulnerabilidade insere-se na categoria **A01:2025 – Broken Access Control**. A CWE-22 (*Improper Limitation of a Pathname to a Restricted Directory – 'Path Traversal'*) faz parte da lista de CWEs mapeadas para esta categoria: a falha permite ao atacante aceder a recursos do sistema de ficheiros (neste caso, escrever neles) fora do diretório a que deveria estar restrito, contornando as restrições de acesso pretendidas pela aplicação.

**OWASP ASVS 5.0 – V5.3 File Storage:** o código viola o requisito **5.3.2 (Nível 1)**, que exige que, ao construir caminhos para operações sobre ficheiros, a aplicação utilize dados gerados internamente ou confiáveis em vez de nomes de ficheiro submetidos pelo utilizador. Se for necessário usar nomes ou metadados fornecidos pelo utilizador, estes devem ser sujeitos a validação e sanitização estritas, de forma a prevenir *path traversal*, inclusão de ficheiros locais ou remotos (LFI/RFI) e SSRF.

No método `execute()` original, o parâmetro `fullName`, controlado pelo utilizador, é usado diretamente em `new File(uploadDirectory, fullName)` sem qualquer validação. A correção aplicada em A.5.g (verificação do caminho canónico) passa a cumprir este requisito.

Requisito relacionado: o **5.3.1 (Nível 1)** exige que ficheiros carregados para pastas públicas não sejam executados como código no servidor. O seu cumprimento mitigaria a consequência mais grave do ataque, a execução de uma *webshell* escrita através de *path traversal*.


## C.1 – Workflow CodeQL

Fork do grupo: `https://github.com/RodrigoVitorino/juice-shop`


## C.2 – Execução manual e inicialização da base de dados

O workflow "CodeQL Scan" foi executado manualmente em **Actions → CodeQL Scan → Run workflow** (evento `workflow_dispatch`) e terminou com sucesso.

**Etapa:** a base de dados é inicializada na etapa **Initialize CodeQL**, que corresponde à ação `github/codeql-action/init@v3`.

**Comando** (extraído dos logs):

```
/opt/hostedtoolcache/CodeQL/2.27.3/x64/codeql/codeql database init \
  --force-overwrite \
  --db-cluster /home/runner/work/_temp/codeql_databases \
  --source-root=/home/runner/work/juice-shop/juice-shop \
  --calculate-language-specific-baseline \
  --sublanguage-file-coverage \
  --extractor-include-aliases \
  --language=javascript \
  --codescanning-config=/home/runner/work/_temp/user-config.yaml
```

O comando `codeql database init` cria a estrutura da base de dados para a linguagem `javascript`, que inclui TypeScript, a partir do código-fonte em `--source-root`, usando a configuração definida no workflow (`--codescanning-config`). A extração do código e a finalização da base de dados acontecem nas etapas seguintes (*Autobuild* e *Perform CodeQL Analysis*), seguidas da execução das queries.

**Localização da base de dados:** a opção `--db-cluster` indica que as bases de dados são criadas em `/home/runner/work/_temp/codeql_databases/`, numa subpasta por linguagem (`/home/runner/work/_temp/codeql_databases/javascript`). Este diretório pertence ao *runner*, a máquina virtual temporária do GitHub Actions, que é destruída no fim do job. A base de dados não fica no repositório. O que persiste são os resultados da análise, em formato SARIF, enviados pela etapa *Perform CodeQL Analysis* e consultáveis em **Security → Code scanning**.

## C.3 – SQL Injection (CWE-89) em `routes/search.ts`

**Alerta:** *Database query built from user-controlled sources* (#13), regra CodeQL `js/sql-injection`, severidade **High**, CWEs associadas: CWE-89, CWE-90, CWE-943.

```ts
21  let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
22  criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
23  models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'
        OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

### Source e sink

O CodeQL reporta um caminho de fluxo de dados com 6 passos, todos em `routes/search.ts`:

| Passo | Linha | Nó | Descrição |
|---|---|---|---|
| 1 – **Source** | 21 | `req.query.q` | Parâmetro `q` da query string do pedido HTTP (`GET /rest/products/search?q=...`), controlado pelo utilizador |
| 2 | 21 | `criteria` | O valor é atribuído à variável `criteria` |
| 3 | 22 | `criteria` (ramo `? criteria`) | Se o comprimento for ≤ 200, o operador ternário devolve o valor **inalterado** |
| 4 | 22 | `criteria = ...` | O resultado é atribuído de novo a `criteria` |
| 5 | 23 | `${criteria}` | O valor é interpolado na *template string* da consulta |
| 6 – **Sink** | 23 | `` `SELECT ... ORDER BY name` `` | A string SQL resultante é passada a `models.sequelize.query(...)` e executada na base de dados |

Ao longo do caminho, o valor não passa por nenhuma operação de neutralização de caracteres especiais. A única transformação possível, `substring(0, 200)`, limita apenas o comprimento e nem sequer é aplicada no caminho reportado (passo 3), pelo que o valor original do utilizador chega intacto à instrução SQL.

### Justificação

O CodeQL usa análise de fluxo de dados (*taint tracking*) e identifica que um valor proveniente de uma *source* remota (`req.query`) chega, sem passar por nenhum sanitizador reconhecido, a um *sink* que executa SQL (`sequelize.query`). O input do utilizador é concatenado no texto da instrução SQL em vez de ser passado como parâmetro. Assim, caracteres como `'` e `)` alteram a estrutura da instrução, e não apenas os dados, o que corresponde à definição da CWE-89 (*Improper Neutralization of Special Elements used in an SQL Command*).

**Exemplo de exploração:** um atacante pode fechar a string e os parênteses e acrescentar uma cláusula `UNION`, por exemplo:

```
GET /rest/products/search?q=xyz')) UNION SELECT id, email, password, '4','5','6','7','8','9' FROM Users--
```

A instrução passa a devolver, juntamente com os produtos, os emails e os *hashes* de password de todos os utilizadores. O `--` comenta o resto da instrução original. Também é possível extrair o esquema da base de dados (por exemplo, a partir de `sqlite_master`).

**Correção:** usar consultas parametrizadas (*replacements* / *bind parameters* do Sequelize), por exemplo:

```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :c OR description LIKE :c) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { c: `%${criteria}%` } }
)
```
