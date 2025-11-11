# FD_GR02 — Vazamento Silencioso via Sincronizador Não‑Autorizado
> **Pacote didático completo** para atividade prática de Forense Digital (host + rede + nuvem) **com Docker**.

## 0) Enunciado (Cenário) Completo
Nas madrugadas de 28 a 30/08, a HealthDataOne detectou picos de tráfego atípicos.
Os dados apontavam para um serviço de nuvem não homologado e sem contrato vigente.
O SOC registrou o evento como potencial incidente de segurança com risco a PII.
A prioridade foi preservar evidências e evitar contaminação adicional do ambiente.

Um notebook corporativo Windows 11, usuário m.junior, surgiu como pivô da ocorrência. O EDR sinalizou execuções de PowerShell e criação de tarefa agendada fora do expediente. Indícios sugerem uso de cliente “portable”, sem instalação e com baixa fricção. Houve tentativa de encobrir rastros por limpeza de logs e navegação InPrivate.

Os artefatos coletados incluem EVTX de Security, PowerShell e TaskScheduler. Também há Prefetch, AmCache, JumpLists, RecentFiles e amostra de PCAP do firewall. O CASB reportou violações associadas a domínios externos e Shadow IT. Todos os itens possuem hashes para validação de integridade e cadeia de custódia.

Sua missão é confirmar ou refutar a exfiltração de até 5 mil registros clínicos. Reconstrua a linha do tempo correlacionando host, rede e eventos do CASB. Identifique a ferramenta, técnica, persistência e contas efetivamente utilizadas. Avalie impacto, escopo de dados e obrigações legais sob a LGPD aplicável.

Entregue um relatório executivo e técnico, claro, reprodutível e baseado em evidências. Inclua metodologia, limitações, IoCs, e plano de resposta em 30-60-90 dias. Anexe tabela de timeline em CSV e resumo dos principais achados por componente. Opcionalmente, proponha regras Sigma ou YARA alinhadas aos artefatos encontrados.

Restrições: 
- Não acesse sistemas reais, opere somente com o pacote didático fornecido.
- Registre passos, comandos e justificativas de análise com timestamps e fontes.
- Critérios de avaliação consideram técnica, correlação, clareza e aderência à LGPD.
- Ao final, responda se houve exfiltração, como ocorreu e quais controles prevenirão recorrência.


## 1) Enunciado (Cenário) Resumido
A **HealthDataOne**, clínica que opera prontuários eletrônicos, percebeu picos de tráfego para um serviço de nuvem **não homologado** nas madrugadas de **28 a 30/08**. Um notebook corporativo (Windows 11, usuário `m.junior`) apresentou alertas de **EDR** para execução de **PowerShell** e criação de **tarefa agendada**. Há suspeita de **exfiltração de dados** (PDF/CSV com até 5 mil registros) usando um cliente “portable” (sem instalação) e possíveis tentativas de **cobrir rastros** (limpeza de logs e uso de sessão InPrivate).

A área de TI coletou rapidamente:
1) imagem lógica do disco do notebook;  
2) export do **Event Viewer** (Security, PowerShell/Operational, TaskScheduler), **Prefetch** e **AmCache**;  
3) histórico do navegador corporativo;  
4) amostra de **PCAP** do firewall;  
5) lista de arquivos recentemente acessados na pasta do sistema clínico;  
6) manifesto do **CASB** com domínios `cloudbox-cdn[.]net` e `uploader-edge[.]io`.

**Sua missão:** confirmar/refutar o vazamento, reconstruir a **linha do tempo**, identificar **ferramenta e técnica de exfiltração**, estimar **impacto** e recomendar **controles**.

---

## 2) Objetivos
- Determinar **o que ocorreu**, **como**, **quando** e **por quem** (quando possível).  
- Identificar **técnicas e artefatos forenses** (host, rede e nuvem).  
- Avaliar **impacto** (tipos de dados, volume, sensibilidade).  
- Propor **plano de prevenção e resposta** (curto, médio e longo prazo).

---

## 3) Tarefas/Desafios
1. **Triagem & preservação:** validar integridade das evidências (hashes) e descrever **cadeia de custódia**.  
2. **Linha do tempo unificada:** correlacionar eventos de host (Windows) com rede (PCAP) e CASB.  
3. **Análise de host:**  
   - Prefetch/AmCache: presença e primeira execução de binário “portable”.  
   - PowerShell/Operational: comandos suspeitos (download, env vars, exclusão de logs).  
   - Task Scheduler: tarefa executada fora do expediente.  
   - RecentFiles/JumpLists: acesso a CSV/PDF do sistema clínico.  
4. **Análise de rede:**  
   - Domínios/destinos: `cloudbox-cdn.net`, `uploader-edge.io`, portas e volume.  
   - Padrões de upload (PUT/POST, chunked).  
5. **Nuvem/CASB:** verificar políticas violadas e apps não homologados (“**Shadow IT**”).  
6. **Atribuição técnica:** conta/logon, host, horário, persistência (se existir).  
7. **Estimativa de impacto:** dados **provavelmente** exfiltrados e risco à **LGPD**.  
8. **Recomendações:** contenção, erradicação, hardening, monitoramento e lições aprendidas.  
9. **Artefatos maliciosos:** calcular hash(es), sugerir **regra Sigma** ou **YARA** (opcional).  
10. **Comunicação executiva:** sumário para diretoria (≤ 1 página).

---

## 4) Tópicos obrigatórios do relatório (entrega principal)
1) **Capa e Sumário Executivo** (até 1 página, linguagem não‑técnica).  
2) **Escopo, Premissas e Limitações** (o que foi e não foi analisado).  
3) **Cadeia de Custódia e Integridade** (procedimentos e hashes).  
4) **Metodologia** (normas/boas práticas e ferramentas utilizadas).  
5) **Linha do Tempo Correlacionada** (host + rede + CASB, com UTC‑3).  
6) **Análise Técnica de Host** (artefatos Windows relevantes).  
7) **Análise de Rede** (pcap/flows, domínios, protocolos, volumes).  
8) **Análise de Nuvem/CASB** (políticas violadas, app não homologado).  
9) **Indicadores de Comprometimento (IoCs)** e hipóteses descartadas.  
10) **Estimativa de Impacto e Risco (LGPD)**.  
11) **Conclusões** (o que ocorreu, como, quando, por quem).  
12) **Plano de Prevenção e Resposta (30‑60‑90 dias)** com **responsáveis**.  
13) **Anexos**: tabela de IoCs; timeline (CSV); regras Sigma/YARA (opcional); referências.

---

## 5) Formato e requisitos de entrega
- **Relatório**: PDF (ou DOCX exportado em PDF), **8–12 páginas** (sem contar anexos).  
- **Individual ou equipe**
- Linguagem clara, citação de fontes e **reprodutibilidade** dos passos.

---

## 6) Pacote de evidências (neste repositório)
Este repositório inclui um **pacote didático** em `./evidence/` com **exports sintéticos** (texto/CSV).  
> ⚠️ Eles **não** são arquivos binários reais (.evtx/.pcap), mas simulam os campos essenciais para análise.

**Estrutura**
```
evidence/
  win_evtx/
    Security.evtx.txt
    Microsoft-Windows-PowerShell_Operational.evtx.txt
    TaskScheduler.evtx.txt
  filesystem/
    Prefetch/CBXSYNC.EXE-1234ABCD.pf.txt
    AmCache/AmCache.hve.txt
    RecentFiles.csv
    JumpLists.csv
  network/
    sample.pcap.txt
  casb/
    alerts.csv
  README.md
  hashes.txt     # SHA-256 de cada arquivo
```
Período do incidente: **2025‑08‑28 a 2025‑08‑30 (UTC‑3)**  
Host: **WIN11‑CLIN‑07** | Usuário: **m.junior**

---

## 7) Critérios de avaliação (100,0 pts + bônus)
- **Metodologia & Cadeia de Custódia (10,0 pts)**  
- **Linha do Tempo Correlacionada (10,5 pts)**  
- **Análise de Host (20,0 pts)**  
- **Análise de Rede (10,5 pts)**  
- **Análise CASB/Nuvem (10,0 pts)**  
- **Impacto & LGPD (10,0 pts)**  
- **Plano 30‑60‑90 (10,0 pts)**  
- **Clareza, evidências e reprodutibilidade (20,0 pts)**  
**Bônus (até +20,0 pts):** regra **Sigma** para detectar padrão de execução; regra **YARA** para o binário.

---

## 8) Ambiente Docker (server + workbench)

### 8.1. Pré‑requisitos
- Docker Engine e Docker Compose v2 (comando `docker compose`).  
  Verifique:
  ```bash
  docker --version
  docker compose version
  ```

### 8.2. Subir o ambiente
Na raiz do projeto:
```bash
docker compose up -d --build
```
Isso cria dois serviços:
- **server** (Nginx) → expõe `./evidence/` em `http://localhost:8080/` (navegação de diretório).  
- **workbench** (Ubuntu + Python + tshark) → monta `./evidence` em **read‑only** (`/evidence`) e `./workspace` em `/workspace` (persistente).

### 8.3. Acessar as evidências no navegador
Abra: `http://localhost:8080/`

### 8.4. Entrar no workbench (shell)
```bash
docker compose exec -it workbench bash
```

### 8.5. Gerar uma timeline de exemplo
Dentro do contêiner:
```bash
analyze_timeline.py
ls -l /workspace/timeline.csv
```
O script mescla eventos dos exports (EVTX txt, PCAP txt, CASB CSV, RecentFiles/JumpLists) e cria `timeline.csv` ordenado por timestamp.

### 8.6. Verificar hashes de integridade
No host (Linux/macOS) ou dentro do workbench:
```bash
# no host (Linux)
sha256sum evidence/**/*
# ou no contêiner
sha256sum /evidence/**/* 2>/dev/null | head
```

### 8.7. Trocar as evidências por arquivos **reais**
Substitua os arquivos em `./evidence/` por **.evtx/.pcap** reais. O workbench já possui `tshark`.
Exemplos de uso no contêiner:
```bash
# visualizar estatísticas de um pcap real
tshark -r /evidence/network/capture.pcap -q -z io,phs

# listar eventos HTTP
tshark -r /evidence/network/capture.pcap -Y http -T fields -e frame.time -e ip.dst -e http.request.full_uri | head
```

### 8.8. Logs, status e encerramento
```bash
docker compose ps
docker compose logs -f server
docker compose down -v   # remove containers e volumes anônimos
```

### 8.9. Observações (Linux/WSL/Permissões)
- Se `localhost:8080` não abrir no WSL2, tente `http://127.0.0.1:8080`.  
- Em Linux, se houver erro de permissão em `./workspace`, rode:  
  ```bash
  sudo chown -R $USER:$USER workspace
  ```

---

## 9) Entregáveis (checklist)
- **PDF 8–12 págs** com todos os **tópicos obrigatórios** (seção 4)  
- **CSV da timeline** (anexo)  
- Lista de **IoCs** (anexo)  
- **Regras Sigma/YARA** (opcional, anexo)

---

## 10) Ética e boas práticas
- Não use ambientes reais; trabalhe **apenas** com as evidências fornecidas.  
- Documente suposições e cite referências (livros, normas, blogposts técnicos, RFCs).  
- Mantenha reprodutibilidade (comandos, versões, caminhos).

---

## 11) Estrutura do projeto
```
.
├─ docker-compose.yml
├─ server/
│  ├─ Dockerfile
│  └─ nginx.conf
├─ workbench/
│  ├─ Dockerfile
│  └─ tools/
│     └─ analyze_timeline.py
├─ evidence/        # pacote didático (txt/csv) já incluso
└─ workspace/       # sua pasta de trabalho (persistente)
```
