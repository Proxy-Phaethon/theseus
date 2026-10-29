from core.packets import Packet, PacketStatus


class Extractor:
    name = "Placeholder"
    supported_artefact_types = {"*"}

    def execute(self, packet: Packet) -> Packet:
        return Packet(
            request_id=packet.request_id,
            task_id=packet.task_id,
            parent_task_id=packet.parent_task_id,
            stage="extraction",
            artefact_type=packet.artefact_type,
            input=None,
            source={},
            status=PacketStatus.NOT_IMPLEMENTED,
            data={},
            entities=[],
            related_entities=[],
            provenance={},
            errors=[],
            metadata={},
        )


EXTRACTOR = Extractor()