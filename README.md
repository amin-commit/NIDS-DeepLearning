# Real-Time NIDS built using Machine/Deep Learning

A self-hosted network intrusion detection system (NIDS), built using a collection of CIC-IDS [datasets](https://www.kaggle.com/datasets/dhoogla/cicidscollection), that uses as a Flask server as an endpoint for the classification of network data.
The model was primarily built using the Long Short-Term Memory Architecture, with the idea to learn malicious network patterns, and possibly detect novel attacks.

## Table of Contents

- [Overview](#overview)
- [Findings and Results](#findings-and-results)
- [Repository Structure](#repository-structure)
- [Setup Instructions](#setup-instructions)
- [Limitations](#limitations)

## Overview

This NIDS utilises machine learning to initially identify malicious traffic, and to then classify it as one of seven different labels, DDoS, DoS, Botnet, Bruteforce, Infiltration, Portscan or Webattack. The use of deep learning is for the model to be used for adaptive threat detection,
and to also understand granular attack patterns.

This was then built upon, inspired from the Pipes And Filters design architecture, where a Flask server is self-hosted and providing an interface displaying important metrics such as the time, source and destination IPs, the models' classification and its confidence. This was done in real-time through
the use of a personalised script, which sends the JSON data from NFStream to the Flask server directly through a HTTP POST request.

This project allows you to run this model with your own hardware, and it does not require a lot of storage space (~75mbs). Being localised also has its advantages of having control over your own data, limitless customisation, limiting the potential attack surface, creating your own security controls,
as well as being able to create your own advanced models if you have the data and hardware for it.

## Findings and Results

Testing of the model was done under a controlled setting, limiting any confounding variables. Virtualised machines were used during testing, a 'victim' Debian machine, and an 'attacker' Kali Linux machine to simulate attacks.

### Classification Report

Firstly, in the classification report generated after training, the model was initially evaluated using unseen training data, and received a 0.8188 F1-Score.
This shows around 82% accuracy, however we can see that this is conflicted between infiltration and benign.

| x | precision | recall | f1-score |
|---|---|---|---|
| Benign | 0.8269 | 0.5064 | 0.6281 |
| Botnet | 0.9979 | 0.9808 | 0.9893 |
| Bruteforce | 0.9990 | 0.9910 | 0.9950 |
| DDoS | 0.9434 | 0.9058 | 0.9242 |
| DoS | 0.8460 | 0.9219 | 0.8823 |
| Infiltration | 0.6263 | 0.8477 | 0.7204 |
| Portscan | 0.7163 | 0.9241 | 0.8070 |
| Webattack | 0.8382 | 0.8991 | 0.8676 |
| accuracy | / | / | 0.8188 |
| macro avg | 0.8493 | 0.8721 | 0.8517 |
| weighted avg | 0.8362 | 0.8188 | 0.8140 |

In the classification report below, this is from the model with infiltration removed entirely, and we can see that it has a greater accuracy of around 94%. 

| x | precision | recall | f1-score |
|---|---|---|---|
| Benign | 0.9517 | 0.9223 | 0.9368 |
| Botnet | 0.9979 | 0.9855 | 0.9917 |
| Bruteforce | 1.0000 | 0.9960 | 0.9980 |
| DDoS | 0.9352 | 0.9536 | 0.9443 |
| DoS | 0.8469 | 0.8987 | 0.8720 |
| Portscan | 0.7968 | 0.6450 | 0.7129 |
| Webattack | 0.8997 | 0.9392 | 0.9190 |
| accuracy | / | / | 0.9372 |
| macro avg | 0.9183 | 0.9058 | 0.9107 |
| weighted avg | 0.9374 | 0.9372 | 0.9368 |

To help assist the model in learning the comparison between benign and infiltration better, a few techniques were used, such as SMOTE, where I adjusted the samples of benign and infiltration.
This also included testing with increasing only their samples, hoping that the model would bias learning their patterns more.
The use of different weight options were also used.

I have included the base model and the model with infiltration removed within the server files, and also their python build code.

---

### Scenario Testing

Firstly, the attacker virtual machine sent attacks of **Bruteforce, DoS, Portscan and Webattack** which were all detected and correctly identified by the model. 

Secondly, the models were tested for their benign accuracy, where well-known websites were being used for 5 minute intervals, whilst the model was classifying the traffic.
This was done multiple times on a variety of different websites, and was testing the base model without infiltration removed.

On one test, it captured 105 flows, where 102 were correctly identified, resulting in **97.14%** accuracy, and the average confidence on benign flows was **93.65%**

On another instance, it captured 325 flows, with 309 being correct, resulting in an accuracy of around **95%**

This is to show that although the model was averaging an accuracy of 82%, in some cases it could reach up to 97% accuracy.

---

## Repository Structure 
```
.
├── Flask Server Files          # Files to establish the Flask Server, with the interface + code for the model to classify traffic
├── Python Capture Script       # Script used on the 'victim' virtual machine to send network data to Flask
├── Python Source Files         # Contains Jupyter Notebook files used to create models
├── .gitignore                  # gitignore
├── LICENSE                     # LICENSE
├── README.md                   # README
└── requirements.txt            # Required libraries to run.
```

The dataset used to train the models is **NOT** included within the repository. It is too large. It can be freely downloaded using the link at the start of this page.

## Setup Instructions

The *requirements.txt* file has all the libraries needed for the program to run. Versioning is not included as it would likely not be needed to only run the program. If you would like to build the model yourself,
the versioning of specific libraries are listed at the top of the notebooks.

### Checking Pathways

For the model, the **data_path** would need to be filled.

For the flask server, in **app.py**, the base_dir would need to be filled.

For the capture script, you will need to enter your Flask URL into **flask_url**.

For the capture script, you will also need to input your source into **source''**. For example eth0.

For the capture script, you should also modify the blocklist to add your own rules on which IPs should not be captured, the code to do this is provided within the capture script.

### Building your Own Model

Building your own model should be straight forward. Within the code, it is included to increase the amount of samples per class within the data, under **samples_per_class**.
There is also a preconfigured way to add boosted classes, where you should first name the class within **boosted_classes** and change the amount via **boosted_cap**.

---

## Limitations

This project of mine is limited, but sets good foundations for what is possible.

- The dataset itself was not used to its full potential. As I am limited by my hardware, I was not able to utilise the entire dataset, therefore I did not get the best possible model.

- This model is not ready for production use. It would not be smart to use this within a working environment in its current state. For example, it should have its own dedicated server, not a localhost instance.

- Testing the capacity of the model was limited, as I did not have the ability to simulate certain attacks such as botnet attacks.

Regardless of these limitations, this should not stop you if you have the hardware to push the model to its limits.

