<div align="center">

<pre>
                                                  
                                                  
           ███                      ███           
         ████████                ████████         
        ██████████   ██    ██  ███████████        
       ███     ████████    ████████     ███       
       █▒█        ████      ████        █▒█       
       █▓█     ███ █          █ ███     █▓█       
       ███        █            █        ███       
       ███         ██        ██         ███       
        ███         ██      ██         ███        
           ██       ██      ██       ██           
                    ███    ███                    
                      █    █                      
                      █    █                      
                                                  
                       █  █                       
                                                  
                                                  
</pre>

</div>

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge\&logo=python\&logoColor=white)

# Theseus

Theseus is an extensible OSINT investigation tool designed to explore publicly available information, investigate digital targets, and organize findings into structured reports.

Give Theseus a target, and it investigates the information associated with it using a growing collection of intelligence-gathering capabilities. Its own tools and integrations with existing services work together within a unified investigation environment, helping investigators move from an initial lead toward a more coherent picture.

Theseus is an **internet explorer, not a search engine**. It is built to investigate, not merely retrieve: examining digital footprints, uncovering connections, and organizing findings that can support further investigation.

---

## Current Status

**Current release:** v0.7.0

**Development stage:** Collector Architecture Overhaul

Theseus is transitioning to a registry-based architecture designed to support multiple entity types, specialized collectors, and structured investigation reports.

The current pipeline implements **email investigation**. Other entity types are registered within the architecture but are not yet supported by the new investigation workflow.

Development is progressing toward v1.0.0, which will establish the first stable release of the email investigation workflow.

## Installation

Theseus is designed to run as a command-line application. Users should be able to launch it by typing `theseus` in their terminal without manually activating a Python virtual environment.

We recommend [pipx](https://pipx.pypa.io/stable/), which installs command-line applications in isolated environments while making their commands available from the terminal.

### Requirements

- Python 3.10 or later
- Git
- pipx

Install pipx if it is not already available on your system. On macOS with Homebrew:

```bash
brew install pipx
pipx ensurepath
```

Restart your terminal if necessary.

### Install Theseus

After the corrected v0.7.1 release has been published, install it with:

```bash
pipx install "git+https://github.com/Proxy-Phaethon/theseus.git@v0.7.1"
```

Launch Theseus:

```bash
theseus
```

No manual virtual-environment activation is required.

### Update Theseus

To install a newer release:

```bash
pipx upgrade theseus
```

If you need to install a particular tagged version:

```bash
pipx install --force "git+https://github.com/Proxy-Phaethon/theseus.git@v0.7.1"
```

### Uninstall Theseus

```bash
pipx uninstall theseus
```

This removes the pipx installation without requiring you to delete your development repository.

## Usage

Start Theseus:

```bash
theseus
```

Enter a target at the prompt:

```text
> someone@example.com
```

Theseus identifies the target type and routes it through the available investigation workflow. During execution, the terminal interface displays progress. When collection finishes, the email responder organizes the results into a structured report.

### Available commands

At the Theseus prompt:

- `help` displays available commands.
- `about` describes the project.
- `status` displays implementation status for registered entity types.
- `history` displays previous targets entered during the session.
- `clear` clears the terminal.
- `q` exits Theseus.

### Current investigation support

Email addresses are currently supported by the new investigation pipeline.

Other entity types may be recognized by the identifier, but recognition does not mean their investigation workflows are implemented. Theseus will report when a workflow is unavailable rather than treating an unsupported target as a completed investigation.

## How Theseus Works

Theseus separates target identification, collection, execution, and report presentation.

**Identifier:** Determines the type of target supplied by the user.

**Collector Registry:** Defines the available investigation components for each entity type.

**Executor:** Runs the applicable normalizer and collectors, records execution outcomes, and isolates individual collector failures.

**Responders:** Organize collected observations into a structured investigation report.

**Terminal Interface:** Provides the interactive CLI, progress feedback, commands, and report presentation.

This separation allows investigation capabilities to grow without placing all collection and presentation logic inside the main application.

## Email Investigation

Email investigation is the first workflow being developed within the new architecture.

Depending on the available information, the report can include:

- **Email validation:** Address syntax and normalization.
- **Domain information:** Information associated with the email domain.
- **Mail infrastructure:** Mail exchange records.
- **Email security:** Available DNS-based email security observations.
- **Breach exposure:** Results returned by the configured breach lookup.
- **Associated services:** Account-discovery findings where the relevant collectors are implemented.
- **Execution summary:** Collector statuses, elapsed time, and errors.

The information returned depends on the target, the available data, the behavior of external services, and the implementation status of individual collectors.

A successful investigation execution does not mean every check returned a positive finding. Missing records, unavailable sources, inconclusive results, and collector errors must be interpreted separately.

### Interpreting results

Theseus organizes observations to support further investigation. Its reports should not be treated as automatic proof of identity, account ownership, compromise, or malicious activity.

A missing result does not necessarily establish that information does not exist. Findings should be assessed in context and corroborated where appropriate.

## Reliability and Error Handling

An investigation can involve multiple independent collectors. One collector may fail while others return useful results.

Theseus is designed to preserve the outcomes of individual collectors, distinguish execution failures from ordinary negative or inconclusive results, and present the findings that remain available.

The objective is to make the investigation process transparent rather than allowing one failed source to invalidate the entire report.

## Contributing

Contributions, bug reports, and suggestions are welcome. When reporting a problem, include the operating system, Python version, installation method, relevant command output, and steps needed to reproduce it. Never include private credentials or sensitive investigation data.

## Documentation

- **[Wiki](https://github.com/Proxy-Phaethon/theseus/wiki):** Detailed project documentation, technical references, and investigation-specific information.
- **[Releases](https://github.com/Proxy-Phaethon/theseus/releases):** Version history, release notes, and changes between releases.

## License

Theseus is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.

<div align="center"> <pre>
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░░▒▓███████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
</pre>