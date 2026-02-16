# import argparse
# import cv2
# import numpy as np
# from dataclasses import dataclass
# from typing import Dict, List, Optional, Tuple
#
# from insightface.app import FaceAnalysis
# from ultralytics import YOLO
#
#
# def imread_unicode(path: str):
#     data = np.fromfile(path, dtype=np.uint8)
#     return cv2.imdecode(data, cv2.IMREAD_COLOR)
#
# def pick_primary_face(faces):
#     if not faces:
#         return None
#     areas = [(f.bbox[2]-f.bbox[0]) * (f.bbox[3]-f.bbox[1]) for f in faces]
#     return faces[int(np.argmax(areas))]
#
# def l2norm(v: np.ndarray, eps: float = 1e-12) -> np.ndarray:
#     v = np.asarray(v, dtype=np.float32).reshape(-1)
#     return v / (np.linalg.norm(v) + eps)
#
# def bbox_iou(a_xyxy: np.ndarray, b_xyxy: np.ndarray) -> float:
#     ax1, ay1, ax2, ay2 = a_xyxy
#     bx1, by1, bx2, by2 = b_xyxy
#     ix1, iy1 = max(ax1, bx1), max(ay1, by1)
#     ix2, iy2 = min(ax2, bx2), min(ay2, by2)
#     iw, ih = max(0.0, ix2 - ix1), max(0.0, iy2 - iy1)
#     inter = iw * ih
#     area_a = max(0.0, ax2 - ax1) * max(0.0, ay2 - ay1)
#     area_b = max(0.0, bx2 - bx1) * max(0.0, by2 - by1)
#     union = area_a + area_b - inter + 1e-12
#     return float(inter / union)
#
# def assign_face_to_person(face_xyxy: np.ndarray, person_boxes_xyxy: np.ndarray) -> Optional[int]:
#     """
#     Robust face->person assignment:
#     - Prefer person boxes that contain face center
#     - Choose the one with best IoU among those
#     - Fallback to best IoU overall if none contain center
#     """
#     if person_boxes_xyxy is None or len(person_boxes_xyxy) == 0:
#         return None
#
#     x1, y1, x2, y2 = face_xyxy
#     cx, cy = 0.5*(x1+x2), 0.5*(y1+y2)
#
#     inside = []
#     for i, (px1, py1, px2, py2) in enumerate(person_boxes_xyxy):
#         if (cx >= px1) and (cx <= px2) and (cy >= py1) and (cy <= py2):
#             inside.append(i)
#
#     if inside:
#         best_i = None
#         best_score = -1.0
#         for i in inside:
#             s = bbox_iou(face_xyxy, person_boxes_xyxy[i])
#             if s > best_score:
#                 best_score = s
#                 best_i = i
#         return best_i
#
#     # fallback
#     ious = [bbox_iou(face_xyxy, pb) for pb in person_boxes_xyxy]
#     best_i = int(np.argmax(ious))
#     if ious[best_i] < 1e-4:
#         return None
#     return best_i
#
#
# @dataclass
# class Track:
#     tid: int
#     bbox: np.ndarray  # (4,) float xyxy
#     last_seen: int
#
#
# def match_tracks_to_dets(tracks: List[Track], det_boxes: np.ndarray, iou_thresh: float):
#     if len(tracks) == 0:
#         return [], [], list(range(len(det_boxes)))
#     if len(det_boxes) == 0:
#         return [], list(range(len(tracks))), []
#
#     pairs = []
#     for ti, t in enumerate(tracks):
#         for di, dbox in enumerate(det_boxes):
#             iou = bbox_iou(t.bbox, dbox)
#             if iou >= iou_thresh:
#                 pairs.append((iou, ti, di))
#     pairs.sort(key=lambda x: x[0], reverse=True)
#
#     used_t, used_d = set(), set()
#     matches = []
#     for iou, ti, di in pairs:
#         if ti in used_t or di in used_d:
#             continue
#         used_t.add(ti)
#         used_d.add(di)
#         matches.append((ti, di))
#
#     unmatched_tracks = [i for i in range(len(tracks)) if i not in used_t]
#     unmatched_dets = [i for i in range(len(det_boxes)) if i not in used_d]
#     return matches, unmatched_tracks, unmatched_dets
#
#
# def compute_owner_map_from_masks(mask_data: np.ndarray, w: int, h: int):
#     """
#     mask_data: (N, mh, mw) float [0..1] (YOLO internal mask resolution)
#     Returns:
#       max_val: (h,w) float32  - max mask prob across persons
#       owner : (h,w) int32     - which person index owns this pixel
#     Uses streaming argmax to avoid (N*h*w) memory blowup.
#     """
#     max_val = np.zeros((h, w), dtype=np.float32)
#     owner = np.full((h, w), -1, dtype=np.int32)
#
#     for i in range(mask_data.shape[0]):
#         mi = cv2.resize(mask_data[i].astype(np.float32), (w, h), interpolation=cv2.INTER_LINEAR)
#         upd = mi > max_val
#         max_val[upd] = mi[upd]
#         owner[upd] = i
#
#     return max_val, owner
#
#
# def main():
#     ap = argparse.ArgumentParser()
#     ap.add_argument("--query", required=True)
#     ap.add_argument("--video", required=True)
#     ap.add_argument("--out", required=True)
#
#     ap.add_argument("--yolo-model", default="yolov8n-seg.pt")
#     ap.add_argument("--yolo-imgsz", type=int, default=640)
#     ap.add_argument("--person-conf", type=float, default=0.35)
#
#     ap.add_argument("--sim-threshold", type=float, default=0.35)
#     ap.add_argument("--keep-ttl", type=int, default=20)
#     ap.add_argument("--mask-threshold", type=float, default=0.25,  # lower = more aggressive blackout
#                     help="Pixel is considered 'person' if max mask prob >= this")
#     ap.add_argument("--dilate", type=int, default=2,
#                     help="Dilate blackout mask by N pixels to prevent edge leaks (0 disables).")
#
#     ap.add_argument("--person-iou-track", type=float, default=0.30)
#     ap.add_argument("--max-track-age", type=int, default=60)
#
#     ap.add_argument("--face-det-size", type=int, default=640)
#     ap.add_argument("--use-gpu-face", action="store_true")
#     ap.add_argument("--insightface-root", default=None)
#
#     ap.add_argument("--lock-target", action="store_true",
#                     help="Once target is found, do NOT switch to another person while TTL is active (prevents overlap jitter).")
#     args = ap.parse_args()
#
#     # ---- InsightFace ----
#     providers = (["CUDAExecutionProvider", "CPUExecutionProvider"]
#                  if args.use_gpu_face else ["CPUExecutionProvider"])
#     fa_kwargs = dict(name="buffalo_l", providers=providers, allowed_modules=["detection", "recognition"])
#     if args.insightface_root:
#         fa_kwargs["root"] = args.insightface_root
#
#     face_app = FaceAnalysis(**fa_kwargs)
#     face_app.prepare(ctx_id=0 if args.use_gpu_face else -1, det_size=(args.face_det_size, args.face_det_size))
#
#     qimg = imread_unicode(args.query)
#     if qimg is None:
#         raise RuntimeError(f"Cannot read query image: {args.query}")
#     qfaces = face_app.get(qimg)
#     qface = pick_primary_face(qfaces)
#     if qface is None:
#         raise RuntimeError("No face detected in query image.")
#     q = l2norm(qface.normed_embedding.astype(np.float32))
#
#     # ---- YOLO Seg ----
#     person_model = YOLO(args.yolo_model)
#
#     # ---- Video IO ----
#     cap = cv2.VideoCapture(args.video)
#     if not cap.isOpened():
#         raise RuntimeError(f"Cannot open video: {args.video}")
#
#     fps = cap.get(cv2.CAP_PROP_FPS)
#     if fps <= 1e-3:
#         fps = 30.0
#
#     W = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
#     H = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
#
#     out = cv2.VideoWriter(args.out, cv2.VideoWriter_fourcc(*"mp4v"), fps, (W, H))
#     if not out.isOpened():
#         raise RuntimeError(f"Cannot open output writer: {args.out}")
#
#     # ---- Tracking + single target state ----
#     tracks: Dict[int, Track] = {}
#     next_tid = 1
#     frame_idx = 0
#
#     target_tid: Optional[int] = None
#     target_until: int = -1
#
#     while True:
#         ok, frame = cap.read()
#         if not ok:
#             break
#         frame_idx += 1
#
#         # 1) Person segmentation
#         yres = person_model.predict(
#             frame, imgsz=args.yolo_imgsz, conf=args.person_conf, classes=[0], verbose=False
#         )[0]
#
#         if yres.boxes is None or len(yres.boxes) == 0:
#             person_boxes = np.zeros((0, 4), dtype=np.float32)
#             mask_data = None
#         else:
#             person_boxes = yres.boxes.xyxy.detach().cpu().numpy().astype(np.float32)
#             if yres.masks is not None and yres.masks.data is not None:
#                 mask_data = yres.masks.data.detach().cpu().numpy().astype(np.float32)  # (N, mh, mw)
#             else:
#                 mask_data = None
#
#         # 2) Update person tracks (IoU)
#         track_ids = list(tracks.keys())
#         track_list = [tracks[tid] for tid in track_ids]
#
#         matches, _, unmatched_det = match_tracks_to_dets(track_list, person_boxes, args.person_iou_track)
#
#         det_to_tid: Dict[int, int] = {}
#
#         for t_i, d_i in matches:
#             tid = track_ids[t_i]
#             tr = tracks[tid]
#             tr.bbox = person_boxes[d_i]
#             tr.last_seen = frame_idx
#             det_to_tid[d_i] = tid
#
#         for d_i in unmatched_det:
#             tid = next_tid
#             next_tid += 1
#             tracks[tid] = Track(tid=tid, bbox=person_boxes[d_i], last_seen=frame_idx)
#             det_to_tid[d_i] = tid
#
#         # Drop stale tracks
#         stale = [tid for tid, tr in tracks.items() if (frame_idx - tr.last_seen) > args.max_track_age]
#         for tid in stale:
#             del tracks[tid]
#
#         # 3) Face matching on this frame => choose ONE best match
#         faces = face_app.get(frame)
#
#         best_det_idx = None
#         best_sim = -1.0
#
#         for f in faces:
#             sim = float(np.dot(q, f.normed_embedding.astype(np.float32)))
#             if sim < args.sim_threshold:
#                 continue
#             det_idx = assign_face_to_person(f.bbox.astype(np.float32), person_boxes)
#             if det_idx is None:
#                 continue
#             if sim > best_sim:
#                 best_sim = sim
#                 best_det_idx = det_idx
#
#         # 4) Update global target (single target only)
#         if best_det_idx is not None and best_det_idx in det_to_tid:
#             cand_tid = det_to_tid[best_det_idx]
#
#             if (not args.lock_target) or (target_tid is None) or (frame_idx > target_until) or (cand_tid == target_tid):
#                 target_tid = cand_tid
#                 target_until = frame_idx + args.keep_ttl
#
#         # Determine which detection index is the current target (if active)
#         target_det_idx = None
#         if target_tid is not None and frame_idx <= target_until:
#             for d_i, tid in det_to_tid.items():
#                 if tid == target_tid:
#                     target_det_idx = d_i
#                     break
#
#         # 5) Build blackout mask with overlap-safe ownership
#         blackout = np.zeros((H, W), dtype=bool)
#
#         if mask_data is not None and mask_data.shape[0] == len(person_boxes) and len(person_boxes) > 0:
#             max_val, owner = compute_owner_map_from_masks(mask_data, W, H)
#             person_pixels = (max_val >= args.mask_threshold)
#
#             if target_det_idx is None:
#                 # Privacy-first: no confident target -> blackout all persons
#                 blackout = person_pixels
#             else:
#                 blackout = person_pixels & (owner != target_det_idx)
#
#         else:
#             # Fallback (no seg masks): blackout all non-target person bboxes
#             for d_i in range(len(person_boxes)):
#                 if target_det_idx is not None and d_i == target_det_idx:
#                     continue
#                 x1, y1, x2, y2 = person_boxes[d_i]
#                 x1 = int(max(0, min(W - 1, x1)))
#                 y1 = int(max(0, min(H - 1, y1)))
#                 x2 = int(max(0, min(W, x2)))
#                 y2 = int(max(0, min(H, y2)))
#                 blackout[y1:y2, x1:x2] = True
#
#         # Optional: dilate blackout to prevent boundary leaks
#         if args.dilate > 0:
#             k = 2 * args.dilate + 1
#             kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (k, k))
#
#             # First dilate (expand mask)
#             blackout = cv2.dilate(blackout.astype(np.uint8), kernel, iterations=1)
#
#             # Optional small blur + threshold to remove jagged edges
#             blackout = cv2.GaussianBlur(blackout.astype(np.float32), (0, 0), sigmaX=1.2)
#             blackout = (blackout > 0.2).astype(bool)
#
#         # Extra safety: blackout any non-target face not covered by person masks (YOLO miss)
#         for f in faces:
#             sim = float(np.dot(q, f.normed_embedding.astype(np.float32)))
#             if sim >= args.sim_threshold:
#                 continue  # keep target face
#             x1, y1, x2, y2 = f.bbox.astype(np.int32).tolist()
#             x1 = max(0, min(W - 1, x1)); y1 = max(0, min(H - 1, y1))
#             x2 = max(0, min(W, x2));     y2 = max(0, min(H, y2))
#             blackout[y1:y2, x1:x2] = True
#
#         out_frame = frame.copy()
#         out_frame[blackout] = 0
#         out.write(out_frame)
#
#     cap.release()
#     out.release()
#     print("Saved:", args.out)
#
#
# if __name__ == "__main__":
#     main()

import argparse
import cv2
import numpy as np
from typing import Optional

from insightface.app import FaceAnalysis
from ultralytics import YOLO


def imread_unicode(path: str):
    data = np.fromfile(path, dtype=np.uint8)
    return cv2.imdecode(data, cv2.IMREAD_COLOR)

def pick_primary_face(faces):
    if not faces:
        return None
    areas = [(f.bbox[2]-f.bbox[0]) * (f.bbox[3]-f.bbox[1]) for f in faces]
    return faces[int(np.argmax(areas))]

def l2norm(v: np.ndarray, eps: float = 1e-12) -> np.ndarray:
    v = np.asarray(v, dtype=np.float32).reshape(-1)
    return v / (np.linalg.norm(v) + eps)

def bbox_iou(a_xyxy: np.ndarray, b_xyxy: np.ndarray) -> float:
    ax1, ay1, ax2, ay2 = a_xyxy
    bx1, by1, bx2, by2 = b_xyxy
    ix1, iy1 = max(ax1, bx1), max(ay1, by1)
    ix2, iy2 = min(ax2, bx2), min(ay2, by2)
    iw, ih = max(0.0, ix2 - ix1), max(0.0, iy2 - iy1)
    inter = iw * ih
    area_a = max(0.0, ax2 - ax1) * max(0.0, ay2 - ay1)
    area_b = max(0.0, bx2 - bx1) * max(0.0, by2 - by1)
    union = area_a + area_b - inter + 1e-12
    return float(inter / union)

def assign_face_to_person(face_xyxy: np.ndarray, person_boxes_xyxy: np.ndarray) -> Optional[int]:
    """
    Robust face->person assignment:
    - Prefer person boxes that contain face center
    - Choose the one with best IoU among those
    - Fallback to best IoU overall if none contain center
    """
    if person_boxes_xyxy is None or len(person_boxes_xyxy) == 0:
        return None

    x1, y1, x2, y2 = face_xyxy
    cx, cy = 0.5*(x1+x2), 0.5*(y1+y2)

    inside = []
    for i, (px1, py1, px2, py2) in enumerate(person_boxes_xyxy):
        if (cx >= px1) and (cx <= px2) and (cy >= py1) and (cy <= py2):
            inside.append(i)

    if inside:
        best_i = None
        best_score = -1.0
        for i in inside:
            s = bbox_iou(face_xyxy, person_boxes_xyxy[i])
            if s > best_score:
                best_score = s
                best_i = i
        return best_i

    # fallback
    ious = [bbox_iou(face_xyxy, pb) for pb in person_boxes_xyxy]
    best_i = int(np.argmax(ious))
    if ious[best_i] < 1e-4:
        return None
    return best_i


def compute_owner_map_from_masks(mask_data: np.ndarray, w: int, h: int):
    """
    mask_data: (N, mh, mw) float [0..1] (YOLO internal mask resolution)
    Returns:
      max_val: (h,w) float32  - max mask prob across persons
      owner : (h,w) int32     - which person index owns this pixel
    Uses streaming argmax to avoid (N*h*w) memory blowup.
    """
    max_val = np.zeros((h, w), dtype=np.float32)
    owner = np.full((h, w), -1, dtype=np.int32)

    for i in range(mask_data.shape[0]):
        mi = cv2.resize(mask_data[i].astype(np.float32), (w, h), interpolation=cv2.INTER_LINEAR)
        upd = mi > max_val
        max_val[upd] = mi[upd]
        owner[upd] = i

    return max_val, owner


def dilate_bool(mask: np.ndarray, pixels: int) -> np.ndarray:
    if pixels <= 0:
        return mask
    k = 2 * pixels + 1
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (k, k))
    return cv2.dilate(mask.astype(np.uint8), kernel, iterations=1).astype(bool)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", required=True)
    ap.add_argument("--video", required=True)
    ap.add_argument("--out", required=True)

    ap.add_argument("--yolo-model", default="yolov8n-seg.pt")
    ap.add_argument("--yolo-imgsz", type=int, default=640)
    ap.add_argument("--person-conf", type=float, default=0.35)

    # YOLO built-in tracking (ByteTrack / BoT-SORT)
    ap.add_argument("--tracker", type=str, default="bytetrack.yaml",
                    help="Ultralytics tracker config: bytetrack.yaml or botsort.yaml")
    ap.add_argument("--lock-target", action="store_true",
                    help="Once target is found, do NOT switch to another person while TTL is active.")

    ap.add_argument("--sim-threshold", type=float, default=0.35)
    ap.add_argument("--keep-ttl", type=int, default=20)

    ap.add_argument("--mask-threshold", type=float, default=0.25,
                    help="Pixel is considered 'person' if max mask prob >= this (lower = more aggressive blackout).")

    # Mask buffers
    ap.add_argument("--dilate", type=int, default=3,
                    help="Extra buffer around BLACKOUT mask (expand) in pixels. 0 disables.")
    ap.add_argument("--protect-dilate", type=int, default=2,
                    help="Extra buffer around TARGET mask (protect) in pixels so blackout dilation never eats target.")

    ap.add_argument("--face-det-size", type=int, default=640)
    ap.add_argument("--use-gpu-face", action="store_true")
    ap.add_argument("--insightface-root", default=None)

    args = ap.parse_args()

    # ---- InsightFace ----
    providers = (["CUDAExecutionProvider", "CPUExecutionProvider"]
                 if args.use_gpu_face else ["CPUExecutionProvider"])
    fa_kwargs = dict(name="buffalo_l", providers=providers, allowed_modules=["detection", "recognition"])
    if args.insightface_root:
        fa_kwargs["root"] = args.insightface_root

    face_app = FaceAnalysis(**fa_kwargs)
    face_app.prepare(ctx_id=0 if args.use_gpu_face else -1, det_size=(args.face_det_size, args.face_det_size))

    qimg = imread_unicode(args.query)
    if qimg is None:
        raise RuntimeError(f"Cannot read query image: {args.query}")
    qfaces = face_app.get(qimg)
    qface = pick_primary_face(qfaces)
    if qface is None:
        raise RuntimeError("No face detected in query image.")
    q = l2norm(qface.normed_embedding.astype(np.float32))

    # Optional: query template with flip (often improves robustness)
    qimg_flip = cv2.flip(qimg, 1)
    qfaces2 = face_app.get(qimg_flip)
    qface2 = pick_primary_face(qfaces2)
    if qface2 is not None:
        q = l2norm(q + qface2.normed_embedding.astype(np.float32))

    # ---- YOLO Seg + Tracking ----
    person_model = YOLO(args.yolo_model)

    # ---- Video IO ----
    cap = cv2.VideoCapture(args.video)
    if not cap.isOpened():
        raise RuntimeError(f"Cannot open video: {args.video}")

    fps = cap.get(cv2.CAP_PROP_FPS)
    if fps <= 1e-3:
        fps = 30.0

    W = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    H = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    out = cv2.VideoWriter(args.out, cv2.VideoWriter_fourcc(*"mp4v"), fps, (W, H))
    if not out.isOpened():
        raise RuntimeError(f"Cannot open output writer: {args.out}")

    # ---- Single target state (track ID) ----
    frame_idx = 0
    target_track_id: Optional[int] = None
    target_until: int = -1

    while True:
        ok, frame = cap.read()
        if not ok:
            break
        frame_idx += 1

        # 1) Person segmentation WITH tracking IDs
        # persist=True keeps tracker state across frames (critical)
        yres = person_model.track(
            frame,
            imgsz=args.yolo_imgsz,
            conf=args.person_conf,
            classes=[0],
            persist=True,
            tracker=args.tracker,
            verbose=False,
        )[0]

        if yres.boxes is None or len(yres.boxes) == 0:
            person_boxes = np.zeros((0, 4), dtype=np.float32)
            track_ids = np.zeros((0,), dtype=np.int32)
            mask_data = None
        else:
            person_boxes = yres.boxes.xyxy.detach().cpu().numpy().astype(np.float32)

            # Track IDs come from yres.boxes.id (may be None in rare cases)
            if getattr(yres.boxes, "id", None) is not None and yres.boxes.id is not None:
                track_ids = yres.boxes.id.detach().cpu().numpy().astype(np.int32)
            else:
                # If tracker didn't provide IDs, fall back to -1 IDs (targeting becomes harder)
                track_ids = np.full((len(person_boxes),), -1, dtype=np.int32)

            if yres.masks is not None and yres.masks.data is not None:
                mask_data = yres.masks.data.detach().cpu().numpy().astype(np.float32)  # (N, mh, mw)
            else:
                mask_data = None

        # 2) Face matching => pick ONE best matching person detection
        faces = face_app.get(frame)
        best_det_idx = None
        best_sim = -1.0

        for f in faces:
            sim = float(np.dot(q, f.normed_embedding.astype(np.float32)))
            if sim < args.sim_threshold:
                continue
            det_idx = assign_face_to_person(f.bbox.astype(np.float32), person_boxes)
            if det_idx is None:
                continue
            if sim > best_sim:
                best_sim = sim
                best_det_idx = det_idx

        # 3) Update global target track ID (single target)
        if best_det_idx is not None and len(track_ids) > best_det_idx:
            cand_id = int(track_ids[best_det_idx])

            # If cand_id is -1, the tracker didn't return an ID; ignore this update.
            if cand_id != -1:
                if (not args.lock_target) or (target_track_id is None) or (frame_idx > target_until) or (cand_id == target_track_id):
                    target_track_id = cand_id
                    target_until = frame_idx + args.keep_ttl

        # 4) Find which detection index is the current target this frame (by track ID)
        target_det_idx = None
        if target_track_id is not None and frame_idx <= target_until:
            hits = np.where(track_ids == target_track_id)[0]
            if hits.size > 0:
                target_det_idx = int(hits[0])

        # 5) Build blackout mask with overlap-safe ownership
        blackout = np.zeros((H, W), dtype=bool)
        target_keep_mask = None  # used to protect target from dilation

        if mask_data is not None and mask_data.shape[0] == len(person_boxes) and len(person_boxes) > 0:
            max_val, owner = compute_owner_map_from_masks(mask_data, W, H)
            person_pixels = (max_val >= args.mask_threshold)

            if target_det_idx is None:
                # Privacy-first: no confident target => blackout all persons
                blackout = person_pixels
            else:
                blackout = person_pixels & (owner != target_det_idx)

                # Build a protection mask for the target pixels so dilation won't eat it
                target_pixels = person_pixels & (owner == target_det_idx)
                target_keep_mask = dilate_bool(target_pixels, args.protect_dilate)

        else:
            # Fallback (no seg masks): blackout all non-target person bboxes
            for d_i in range(len(person_boxes)):
                if target_det_idx is not None and d_i == target_det_idx:
                    continue
                x1, y1, x2, y2 = person_boxes[d_i]
                x1 = int(max(0, min(W - 1, x1)))
                y1 = int(max(0, min(H - 1, y1)))
                x2 = int(max(0, min(W, x2)))
                y2 = int(max(0, min(H, y2)))
                blackout[y1:y2, x1:x2] = True

        # 6) Buffer the blackout (stronger masking) BUT never allow it to cover the target
        if args.dilate > 0:
            k = 2 * args.dilate + 1
            kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (k, k))

            # Expand blackout
            blackout_u8 = cv2.dilate(blackout.astype(np.uint8), kernel, iterations=1)

            # Smooth edges (optional) then threshold back
            blackout_f = cv2.GaussianBlur(blackout_u8.astype(np.float32), (0, 0), sigmaX=1.2)
            blackout = (blackout_f > 0.2)

            # Critical: protect target pixels
            if target_keep_mask is not None:
                blackout[target_keep_mask] = False

        # 7) Extra safety: blackout any non-target face not covered by person masks (YOLO miss)
        for f in faces:
            sim = float(np.dot(q, f.normed_embedding.astype(np.float32)))
            if sim >= args.sim_threshold:
                continue  # keep target face
            x1, y1, x2, y2 = f.bbox.astype(np.int32).tolist()
            x1 = max(0, min(W - 1, x1)); y1 = max(0, min(H - 1, y1))
            x2 = max(0, min(W, x2));     y2 = max(0, min(H, y2))
            blackout[y1:y2, x1:x2] = True

        out_frame = frame.copy()
        out_frame[blackout] = 0
        out.write(out_frame)

    cap.release()
    out.release()
    print("Saved:", args.out)


if __name__ == "__main__":
    main()
