from pathlib import Path

import fitz

from core.packets import Packet, PacketStatus

def _clean_metadata(metadata):
    """Normalise PDF metadata values."""

    if not metadata:
        return {}

    return {
        key: value if value not in ("", None) else None
        for key, value in metadata.items()
    }

def _extract_page(page, page_number):
    """Extract text and structural metadata from one PDF page."""

    text = page.get_text("text")

    links = []

    for link in page.get_links():
        links.append({
            "type": link.get("kind"),
            "uri": link.get("uri"),
            "page": link.get("page"),
            "file": link.get("file"),
            "destination": link.get("to"),
        })

    annotations = []

    for annotation in page.annots() or []:
        annotations.append({
            "type": annotation.type[1],
            "content": annotation.info.get("content"),
            "title": annotation.info.get("title"),
            "subject": annotation.info.get("subject"),
            "creation_date": annotation.info.get("creationDate"),
            "modification_date": annotation.info.get("modDate"),
        })

    images = page.get_images(full=True)

    return {
        "page_number": page_number,
        "width": round(page.rect.width, 2),
        "height": round(page.rect.height, 2),
        "rotation": page.rotation,
        "text": text,
        "text_length": len(text),
        "has_text": bool(text.strip()),
        "links": links,
        "link_count": len(links),
        "annotations": annotations,
        "annotation_count": len(annotations),
        "images": [
            {
                "xref": image[0],
                "width": image[2],
                "height": image[3],
                "color_space": image[5],
                "bits_per_component": image[4],
            }
            for image in images
        ],
        "image_count": len(images),
    }

def pdfextract(packet: Packet) -> Packet:
    """
    Extract metadata and document structure from a PDF file.

    Input:
        A filesystem path to a PDF document.

    Output:
        Document metadata, page text, links, annotations,
        image references, and table-of-contents entries.
    """

    result = packet.child(
        stage="extraction",
        artefact_type="pdf",
        status=PacketStatus.RUNNING,
    )

    document = None

    try:
        if not isinstance(packet.input, str):
            raise TypeError("PDF input must be a filesystem path.")

        path = Path(packet.input.strip()).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"PDF file does not exist: {path}"
            )

        if not path.is_file():
            raise ValueError("Input must reference a regular file.")

        if path.suffix.lower() != ".pdf":
            raise ValueError("Input file must have a .pdf extension.")

        document = fitz.open(path)

        if document.needs_pass:
            raise PermissionError("PDF is password-protected.")

        pages = [
            _extract_page(page, page_number)
            for page_number, page in enumerate(document, start=1)
        ]

        toc = [
            {
                "level": entry[0],
                "title": entry[1],
                "page": entry[2],
            }
            for entry in document.get_toc()
        ]

        total_text_length = sum(
            page["text_length"] for page in pages
        )

        total_links = sum(
            page["link_count"] for page in pages
        )

        total_annotations = sum(
            page["annotation_count"] for page in pages
        )

        total_images = sum(
            page["image_count"] for page in pages
        )

        result.data = {
            "file": {
                "name": path.name,
                "absolute_path": str(path.resolve()),
                "size_bytes": path.stat().st_size,
            },
            "document": {
                "page_count": document.page_count,
                "metadata": _clean_metadata(document.metadata),
                "is_encrypted": document.is_encrypted,
                "is_pdf": document.is_pdf,
                "is_repaired": document.is_repaired,
                "is_form_pdf": document.is_form_pdf,
            },
            "summary": {
                "total_text_length": total_text_length,
                "total_links": total_links,
                "total_annotations": total_annotations,
                "total_images": total_images,
                "table_of_contents_entries": len(toc),
            },
            "table_of_contents": toc,
            "pages": pages,
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="PDF_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.pdf",
        )

    except PermissionError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="PDF_ACCESS_DENIED",
            message=str(exc),
            component="extractors.pdf",
        )

    except (TypeError, ValueError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_PDF_INPUT",
            message=str(exc),
            component="extractors.pdf",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="PDF_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.pdf",
        )

    finally:
        if document is not None:
            document.close()

    return result