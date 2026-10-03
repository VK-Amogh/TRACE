"""TRACE Neural Fine-Tuning and Training Engine with PyTorch CUDA Acceleration."""

from trace_engine.intelligence.training.dataset import VulnerabilityDataset, generate_cybersecurity_training_corpus
from trace_engine.intelligence.training.trainer import SecureBERTTrainer, TrainingConfig
from trace_engine.intelligence.training.slicer import DataflowSliceExtractor, slice_and_canonicalize
from trace_engine.intelligence.training.lora_system2 import System2LoRATrainer, LoRATrainingConfig
from trace_engine.intelligence.training.dataset_importers import JulietImporter, BigVulImporter, CVEfixesImporter

__all__ = [
    "VulnerabilityDataset",
    "generate_cybersecurity_training_corpus",
    "SecureBERTTrainer",
    "TrainingConfig",
    "DataflowSliceExtractor",
    "slice_and_canonicalize",
    "System2LoRATrainer",
    "LoRATrainingConfig",
    "JulietImporter",
    "BigVulImporter",
    "CVEfixesImporter",
]
