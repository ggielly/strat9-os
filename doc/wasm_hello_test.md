# WASM Hello World Test (strate-wasm)

Fichiers ajoutés:
- `/initfs/strate-wasm` (runtime)
- `/initfs/bin/hello.wasm` (test hello world)
- `/initfs/wasm-test.toml` (exemple de configuration)

## Lancement rapide

Dans le shell Strat9:

```text
wasm-run /initfs/bin/hello.wasm
```

Sortie attendue:

```text
hello world!
```

## Configuration de référence

Le fichier `/initfs/wasm-test.toml` contient un exemple de silo WASM complet:
- une strate runtime `strate-wasm`
- une app `hello.wasm`
