# CTF Challenge Writeup: Northstar FM: Night Signals

**Team:** Code Crew  
**Author:** Arjun Singh Pundir

**Challenge Name:** Northstar FM: Night Signals  
**Points:** 200  
**Category:** Digital Forensics / OSINT  

---

## Challenge Description
The fictional community radio station Northstar FM went quiet in 2019. Its final broadcast, *Night Signals*, was transmitted from a remote relay hut in the fictional county of Larkspur:

> "The station's archive was recovered, but its location field is corrupted. Using the supplied public-record fragments, determine the three-word name of the footbridge nearest the relay hut. Required format: `CTF{old_mill_bridge}`. Everything needed is in the `evidence/` directory."

---

## Step-by-Step Solution

### Step 1: Evidence Discovery and Cataloging
We thoroughly inspected the `evidence/` directory containing archival cards, trail logs, community bulletins, photographs, and civil engineering registers:
1. `Northstar FM Archive Recovery Batch 19-B` (Note Cards 1–3)
2. `Larkspur Town Bulletin (May 2017 – Community Noticeboard)`
3. `Alder Run Volunteer Trail Maintenance Log (Maintainer: "Moss")`
4. `Historical Photo Archive & Captions`
5. `Larkspur County Public Works – Alder Run Footbridge & Plaque Register`

---

### Step 2: Triangulating the Relay Hut Location
By cross-referencing clues across the documents:

1. **Approach & Path Fork:**
   * *Town Bulletin:* The Alder Run Loop trailhead begins at the east gate on Juniper Lane. At the trail fork, the sun marker heads uphill toward Quarry Rise, while the **crescent marker** leads downhill along the river to the lower path.
   * *Note Card 1:* Confirms the relay hut is *not* at Quarry Rise; the operator took the lower footpath from the east gate, choosing the crescent-marked path.
   * *Volunteer Log (2018-09-08):* Confirms the crescent marker guides hikers downhill toward the Alder Run stream.

2. **Sequential Footbridges on Lower Alder Run:**
   * *Volunteer Log (2018-09-09):* Documents the exact topological sequence of footbridges encountered when walking downhill from the east gate:
     1. **AR-14** (1st crossing)
     2. **AR-09** (2nd crossing)
     3. **AR-22** (3rd crossing)
   * The log explicitly notes:
     > *"The relay hut path leaves the main trail immediately after the second crossing. Do not cross the third bridge if you are going to the radio hut."*

3. **Bridge Markers and Identifiers:**
   * *Note Card 2 & 3:* State that water can be heard under the bridge directly from the hut's porch, and that the bridge name is inscribed on a small brass plaque not shown on public trail maps.
   * *Volunteer Log (2019-02-17):* Confirms the maintainer polished the brass dedication plaque on bridge **AR-09**, engraved with the inscription: *"for those who keep a light"*.
   * *Photo Archive:* Shows the western trail sign with three carved stars positioned immediately past the brass-plaqued bridge crossing among the river reeds.

---

### Step 3: Resolving the Bridge Name via Public Works Register
We consulted the official *Larkspur County Public Works Register* for the Alder Run infrastructure assets:

| Asset ID | Bridge Name | Plaque Material & Inscription | Proximity to Relay Hut |
|---|---|---|---|
| **AR-14** | Heron Bend Bridge | Wooden marker; repaired 2015 | 1st crossing; upstream |
| **AR-09** | **Lantern Reed Bridge** | **Brass plaque**; *"for those who keep a light"* | **2nd crossing; immediately adjacent to hut spur path** |
| **AR-22** | Willow Glass Bridge | Aluminum plate; replaced 2016 | 3rd crossing; downstream past hut |

Because the spur path to the relay hut branches off immediately after the second crossing (**AR-09**) and sits right by the brass plaque bridge, the nearest footbridge is **Lantern Reed Bridge**.

---

## Verification
* **Sequence Alignment:** East Gate $\rightarrow$ Crescent Fork $\rightarrow$ AR-14 (1st) $\rightarrow$ **AR-09 (2nd, Relay Hut Turnoff)** $\rightarrow$ AR-22 (3rd).
* **Physical Corroboration:** The brass plaque on AR-09 matches the dedication *"for those who keep a light"* referenced across the operator's notes and the maintenance log.
* **Format:** Exactly 3 lowercase words connected with underscores inside `CTF{...}`.

---

## Flag
```
CTF{lantern_reed_bridge}
```
