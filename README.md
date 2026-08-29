<div align="center"> <pre> 
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░░▒▓███████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
</pre>

</div>

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge\&logo=python\&logoColor=white)

</div>

Theseus is a local Small Language Model (SLM) research assistant designed to operate on [Chaos](https://github.com/Proxy-Phaethon/chaos) research environments.

Where Chaos provides the computational language and persistent structure for a research project, Theseus provides the interactive intelligence that can work with it.

The goal is not to build another chatbot.

The goal is to build a local research system that can acquire knowledge when needed, reason over it, perform computation, and actively work on a persistent research project.

## The Idea

A language model does not need to contain all of the knowledge required to perform research.

It needs to be able to determine what it does not know, find the relevant information, understand that information, and use it appropriately.

Theseus therefore separates the model from the research environment.

```text
                 THESEUS
              Local SLM Agent
                    │
        ┌───────────┼───────────┐
        │           │           │
      SEARCH      CHAOS       TOOLS
        │       WORKSPACE       │
        │           │           │
        └───────────┼───────────┘
                    │
                    ▼
             RESEARCH STATE
```

The SLM provides language understanding and reasoning.

Chaos provides persistent state, structured data, computation, and research artifacts.

External tools provide access to information and capabilities that do not need to exist inside the model itself.

## Chaos + Theseus

A Chaos project can represent an entire research topic.

It can contain questions, notes, sources, data, computations, experiments, results, and other research material.

Theseus can work directly on that project.

```text
Researcher
    │
    ▼
 Theseus
    │
    ├── Understand request
    ├── Inspect research state
    ├── Search external sources
    ├── Retrieve information
    ├── Perform analysis
    ├── Run computations
    └── Update research project
             │
             ▼
          Chaos
             │
      ┌──────┼───────┐
      ▼      ▼       ▼
    State  Data   Results
```

Chaos remains the source of truth.

Theseus is an agent operating on that source of truth.

This means a researcher can work directly with a Chaos project without Theseus, while Theseus can later be introduced as another participant in the same environment.

## Research Model

Theseus is intended to follow a research loop rather than simply generate an answer.

```text
             Question
                │
                ▼
         Understand problem
                │
                ▼
        Inspect current state
                │
          ┌─────┴─────┐
          │           │
       Sufficient?   Missing?
          │           │
          │           ▼
          │       Search / retrieve
          │           │
          └─────┬─────┘
                ▼
             Analyze
                │
                ▼
           Compute / act
                │
                ▼
        Record new knowledge
                │
                ▼
          Updated project
```

The important property is that the result of research does not have to disappear when the conversation ends.

It becomes part of the project.

## Deterministic Computation

Theseus may use a probabilistic language model, but it should not be expected to perform every operation through prediction.

When a task requires exact computation, the operation should be delegated to an appropriate deterministic system.

```text
Natural Language
       │
       ▼
    Theseus
       │
       ├── Interpret
       ├── Plan
       └── Select operation
                 │
                 ▼
               Chaos
                 │
          Deterministic logic
                 │
                 ▼
              Result
                 │
                 ▼
              Theseus
```

This creates a distinction between **reasoning about a computation** and **performing the computation**.

The language model can determine that a calculation needs to happen.

The computational system performs it.

## Capabilities

The intended capabilities include:

* Local SLM inference
* Natural-language interaction
* Web search and information retrieval
* Research-source discovery
* Persistent research context
* Chaos project inspection
* Chaos project modification
* Deterministic computation
* Data analysis
* Research-note generation
* Structured knowledge management
* Tool use
* Long-running research workflows

## Local First

Theseus is designed to run locally.

A local model provides control over the model, its execution environment, and the data surrounding it.

Internet access can be provided as a tool rather than as a requirement for the model itself.

This allows the system to operate in different modes:

```text
LOCAL

Theseus
  │
  ├── Local SLM
  ├── Local Chaos project
  └── Local tools


CONNECTED

Theseus
  │
  ├── Local SLM
  ├── Local Chaos project
  ├── Local tools
  └── Internet / external sources
```

The model does not need to be permanently connected to a remote AI service in order to remain useful.

## Relationship to Chaos

Theseus and Chaos are deliberately separate projects.

**Chaos** is the computational research environment.

**Theseus** is the research assistant.

```text
              CHAOS
       Computational Environment
                 │
        ┌────────┼────────┐
        ▼        ▼        ▼
      State     Data   Computation
        │        │        │
        └────────┼────────┘
                 │
                 ▼
              THESEUS
          Research Assistant
                 │
        ┌────────┼────────┐
        ▼        ▼        ▼
      Search   Reason    Act
```

Chaos should remain useful without Theseus.

Theseus should be able to operate on Chaos without replacing it.

This separation allows the research environment to remain structured, inspectable, and reproducible while the assistant remains replaceable and extensible.

## Development

Theseus is currently in the early stages of development.

The initial work focuses on:

* Establishing the local SLM runtime
* Designing the agent architecture
* Building the Chaos interface
* Implementing tool use
* Establishing research-state management
* Developing retrieval and search capabilities

More advanced research automation will be built on top of these foundations.
